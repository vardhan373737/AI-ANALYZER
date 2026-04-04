const { createSupabaseServiceClient } = require('../config/supabase');
const pdfParse = require('pdf-parse');
const PDFDocument = require('pdfkit');
const fs = require('fs');
const path = require('path');

const supabase = createSupabaseServiceClient();
const storageBucket = process.env.SUPABASE_STORAGE_BUCKET || 'analysis-artifacts';
const threatIntelCache = new Map();
const THREAT_INTEL_TTL_MS = Number(process.env.THREAT_INTEL_CACHE_TTL_MS || 6 * 60 * 60 * 1000);

function toBase64Url(value) {
  return Buffer.from(String(value || ''), 'utf8')
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function getCachedThreatIntel(cacheKey) {
  const cached = threatIntelCache.get(cacheKey);
  if (!cached) {
    return null;
  }

  if (Date.now() > cached.expiresAt) {
    threatIntelCache.delete(cacheKey);
    return null;
  }

  return cached.value;
}

function setCachedThreatIntel(cacheKey, value) {
  threatIntelCache.set(cacheKey, {
    value,
    expiresAt: Date.now() + THREAT_INTEL_TTL_MS
  });
}

async function fetchJsonOrNull(url, options) {
  try {
    const response = await fetch(url, options);
    if (!response.ok) {
      return null;
    }
    return await response.json();
  } catch (error) {
    return null;
  }
}

function getVtClassification(stats) {
  const malicious = Number(stats?.malicious || 0);
  const suspicious = Number(stats?.suspicious || 0);

  if (malicious > 0) {
    return 'malicious';
  }

  if (suspicious > 0) {
    return 'suspicious';
  }

  return 'clean';
}

async function fetchVirusTotalIntel(indicator) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey || !indicator?.value) {
    return null;
  }

  const type = indicator.type;
  const value = String(indicator.value);
  const cacheKey = `vt:${type}:${value}`;
  const cached = getCachedThreatIntel(cacheKey);
  if (cached) {
    return cached;
  }

  let endpoint = null;
  if (type === 'ip') {
    endpoint = `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(value)}`;
  } else if (type === 'domain') {
    endpoint = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(value)}`;
  } else if (type === 'hash') {
    endpoint = `https://www.virustotal.com/api/v3/files/${encodeURIComponent(value)}`;
  } else if (type === 'url') {
    endpoint = `https://www.virustotal.com/api/v3/urls/${toBase64Url(value)}`;
  }

  if (!endpoint) {
    return null;
  }

  const payload = await fetchJsonOrNull(endpoint, {
    method: 'GET',
    headers: { 'x-apikey': apiKey }
  });

  const stats = payload?.data?.attributes?.last_analysis_stats;
  if (!stats) {
    return null;
  }

  const malicious = Number(stats.malicious || 0);
  const suspicious = Number(stats.suspicious || 0);
  const harmless = Number(stats.harmless || 0);
  const undetected = Number(stats.undetected || 0);
  const totalEngines = malicious + suspicious + harmless + undetected;
  const detectionRate = totalEngines ? Number(((malicious + suspicious) / totalEngines).toFixed(2)) : 0;

  const intel = {
    provider: 'virustotal',
    classification: getVtClassification(stats),
    confidence: malicious > 0 ? 0.95 : suspicious > 0 ? 0.78 : harmless > 0 ? 0.2 : 0.35,
    detectionRate,
    stats: {
      malicious,
      suspicious,
      harmless,
      undetected
    }
  };

  setCachedThreatIntel(cacheKey, intel);
  return intel;
}

async function fetchAbuseIpdbIntel(indicator) {
  const apiKey = process.env.ABUSEIPDB_API_KEY;
  if (!apiKey || indicator?.type !== 'ip' || !indicator.value) {
    return null;
  }

  const value = String(indicator.value);
  const cacheKey = `abuseipdb:${value}`;
  const cached = getCachedThreatIntel(cacheKey);
  if (cached) {
    return cached;
  }

  const endpoint = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(value)}&maxAgeInDays=90`;
  const payload = await fetchJsonOrNull(endpoint, {
    method: 'GET',
    headers: {
      Key: apiKey,
      Accept: 'application/json'
    }
  });

  const data = payload?.data;
  if (!data) {
    return null;
  }

  const score = Number(data.abuseConfidenceScore || 0);
  const intel = {
    provider: 'abuseipdb',
    classification: score >= 70 ? 'malicious' : score >= 30 ? 'suspicious' : 'clean',
    confidence: score >= 70 ? 0.92 : score >= 30 ? 0.72 : 0.25,
    abuseConfidenceScore: score,
    usageType: data.usageType || null,
    totalReports: Number(data.totalReports || 0)
  };

  setCachedThreatIntel(cacheKey, intel);
  return intel;
}

async function enrichIocsWithThreatIntel(iocIntel) {
  const indicators = Array.isArray(iocIntel?.indicators) ? iocIntel.indicators : [];
  const limitedIndicators = indicators.slice(0, 40);

  const enrichedIndicators = await Promise.all(
    limitedIndicators.map(async (indicator) => {
      const vtIntel = await fetchVirusTotalIntel(indicator);
      const abuseIpdbIntel = await fetchAbuseIpdbIntel(indicator);
      const external = [vtIntel, abuseIpdbIntel].filter(Boolean);

      const externalConfidence = external.length
        ? Math.max(...external.map((item) => Number(item.confidence || 0)))
        : 0;

      return {
        ...indicator,
        confidence: Math.max(Number(indicator.confidence || 0), externalConfidence),
        tags: [
          ...(indicator.tags || []),
          ...external
            .map((item) => (item.classification === 'malicious' ? 'known-malicious' : item.classification === 'suspicious' ? 'known-suspicious' : null))
            .filter(Boolean)
        ],
        externalIntel: external
      };
    })
  );

  const highConfidenceCount = enrichedIndicators.filter((indicator) => Number(indicator.confidence || 0) >= 0.75).length;
  const maliciousExternalMatches = enrichedIndicators.filter((indicator) =>
    (indicator.externalIntel || []).some((source) => source.classification === 'malicious')
  ).length;

  return {
    ...iocIntel,
    indicators: enrichedIndicators,
    highConfidenceCount,
    externalSummary: {
      virusTotalEnabled: Boolean(process.env.VIRUSTOTAL_API_KEY),
      abuseIpdbEnabled: Boolean(process.env.ABUSEIPDB_API_KEY),
      maliciousExternalMatches
    }
  };
}

function mapMitreAttack({ findings = [], iocIntel = { indicators: [] }, riskEngine = null }) {
  const mapping = new Map();
  const normalizedRiskScore = clampNumber(Number(riskEngine?.score || 0), 0, 100);

  const registerTechnique = (id, name, tactic, reason, options = {}) => {
    if (!mapping.has(id)) {
      mapping.set(id, {
        id,
        name,
        tactic,
        reasons: [],
        evidenceCount: 0,
        score: 0,
        confidence: 0,
        severity: 'low'
      });
    }

    const entry = mapping.get(id);

    if (reason && !entry.reasons.includes(reason)) {
      entry.reasons.push(reason);
    }

    const weight = Number(options.weight || 12);
    const confidence = clampNumber(Number(options.confidence || 0.4), 0, 1);
    const riskBoost = clampNumber(normalizedRiskScore / 100, 0, 1) * 8;
    const contribution = weight + riskBoost;

    entry.evidenceCount += 1;
    entry.score = clampNumber(entry.score + contribution, 0, 100);
    entry.confidence = Math.max(entry.confidence, confidence);

    const severitySource = entry.score * 0.7 + entry.confidence * 30;
    entry.severity = severitySource >= 68 ? 'high' : severitySource >= 42 ? 'medium' : 'low';
  };

  findings.forEach((finding) => {
    const title = String(finding?.title || '').toLowerCase();
    const severity = String(finding?.severity || 'low').toLowerCase();
    const findingConfidence = severity === 'high' ? 0.85 : severity === 'medium' ? 0.72 : 0.55;

    if (title.includes('weak authentication')) {
      registerTechnique('T1078', 'Valid Accounts', 'Persistence', 'Weak authentication patterns detected', {
        weight: 20,
        confidence: findingConfidence
      });
      registerTechnique('T1110', 'Brute Force', 'Credential Access', 'Weak authentication indicators can enable brute-force attempts', {
        weight: 16,
        confidence: findingConfidence
      });
    }

    if (title.includes('injection')) {
      registerTechnique('T1190', 'Exploit Public-Facing Application', 'Initial Access', 'Injection-style patterns were detected', {
        weight: 24,
        confidence: findingConfidence
      });
      registerTechnique('T1059', 'Command and Scripting Interpreter', 'Execution', 'Injection patterns may lead to command/scripting execution', {
        weight: 18,
        confidence: findingConfidence
      });
    }

    if (title.includes('sensitive data exposure')) {
      registerTechnique('T1552', 'Unsecured Credentials', 'Credential Access', 'Sensitive credential-like strings were found', {
        weight: 22,
        confidence: findingConfidence
      });
      registerTechnique('T1530', 'Data from Cloud Storage Object', 'Collection', 'Sensitive data exposure can include cloud object data leakage', {
        weight: 14,
        confidence: findingConfidence
      });
    }

    if (title.includes('unsafe transport')) {
      registerTechnique('T1071.001', 'Web Protocols', 'Command and Control', 'Potentially unsafe transport references were found', {
        weight: 16,
        confidence: findingConfidence
      });
      registerTechnique('T1041', 'Exfiltration Over C2 Channel', 'Exfiltration', 'Unsafe transport can expose traffic to C2-style exfiltration', {
        weight: 13,
        confidence: findingConfidence
      });
    }

    if (title.includes('suspicious process')) {
      registerTechnique('T1059', 'Command and Scripting Interpreter', 'Execution', 'Suspicious scripting/process keywords were detected', {
        weight: 21,
        confidence: findingConfidence
      });
      registerTechnique('T1204', 'User Execution', 'Execution', 'Suspicious process hints may involve user-triggered execution paths', {
        weight: 12,
        confidence: findingConfidence
      });
    }
  });

  (iocIntel.indicators || []).forEach((indicator) => {
    const tags = Array.isArray(indicator?.tags) ? indicator.tags : [];
    const indicatorConfidence = clampNumber(Number(indicator?.confidence || 0.4), 0, 1);

    if (tags.includes('url-shortener')) {
      registerTechnique('T1566.002', 'Spearphishing Link', 'Initial Access', 'Shortened URL IOC matched phishing-like behavior', {
        weight: 20,
        confidence: Math.max(indicatorConfidence, 0.75)
      });
    }

    if (tags.includes('credential-lure')) {
      registerTechnique('T1566.002', 'Spearphishing Link', 'Initial Access', 'Credential lure patterns were seen in links', {
        weight: 22,
        confidence: Math.max(indicatorConfidence, 0.8)
      });
    }

    if (tags.includes('insecure-transport')) {
      registerTechnique('T1071.001', 'Web Protocols', 'Command and Control', 'IOC used insecure web protocol', {
        weight: 14,
        confidence: indicatorConfidence
      });
    }

    if (tags.includes('suspicious-tld')) {
      registerTechnique('T1583.001', 'Acquire Infrastructure: Domains', 'Resource Development', 'Suspicious TLD associated with indicator', {
        weight: 17,
        confidence: Math.max(indicatorConfidence, 0.68)
      });
    }

    if (tags.includes('public-ip')) {
      registerTechnique('T1595', 'Active Scanning', 'Reconnaissance', 'Public IP indicators may relate to scanning or probing activity', {
        weight: 10,
        confidence: indicatorConfidence
      });
    }

    if (tags.includes('known-malicious')) {
      registerTechnique('T1583', 'Acquire Infrastructure', 'Resource Development', 'Indicator matched external malicious intelligence', {
        weight: 26,
        confidence: Math.max(indicatorConfidence, 0.9)
      });
      registerTechnique('T1583.001', 'Acquire Infrastructure: Domains', 'Resource Development', 'Known-malicious indicator linked to hostile infrastructure acquisition', {
        weight: 20,
        confidence: Math.max(indicatorConfidence, 0.85)
      });
    }

    if (tags.includes('known-suspicious')) {
      registerTechnique('T1598', 'Phishing for Information', 'Reconnaissance', 'Indicator matched suspicious reputation from external intelligence', {
        weight: 15,
        confidence: Math.max(indicatorConfidence, 0.7)
      });
    }
  });

  return [...mapping.values()].sort((a, b) => b.score - a.score);
}

function getSupabaseOrFail(res) {
  if (!supabase) {
    res.status(500).json({ message: 'Supabase is not configured. Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY.' });
    return null;
  }

  return supabase;
}

function clampNumber(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

function buildRiskEngine({ baseline = 0, factors = [] }) {
  const normalizedFactors = (factors || [])
    .filter((factor) => Number(factor?.hits ?? factor?.count ?? 0) > 0)
    .map((factor) => ({
      id: factor.id,
      label: factor.label,
      severity: factor.severity,
      hits: Number(factor.hits ?? factor.count ?? 0),
      weight: Number(factor.weight || 0),
      contribution: Number(factor.contribution || 0)
    }))
    .sort((a, b) => b.contribution - a.contribution);

  const weightedScore = normalizedFactors.reduce((sum, factor) => sum + factor.contribution, 0);
  const distinctHighSignals = normalizedFactors.filter((factor) => factor.severity === 'high').length;
  const threatSpreadBonus = clampNumber(normalizedFactors.length * 3, 0, 15);
  const highSignalBonus = distinctHighSignals >= 2 ? 8 : distinctHighSignals === 1 ? 4 : 0;
  const score = clampNumber(Math.round(baseline + weightedScore + threatSpreadBonus + highSignalBonus), 0, 100);
  const level = score >= 70 ? 'High' : score >= 40 ? 'Moderate' : 'Low';

  const threatType =
    level === 'High'
      ? 'Phishing / Malware Risk'
      : level === 'Moderate'
        ? 'Suspicious Activity'
        : 'Likely Safe';

  const explanation =
    level === 'High'
      ? 'Multiple high-confidence and high-impact indicators were detected.'
      : level === 'Moderate'
        ? 'Some suspicious indicators were detected and should be reviewed before trust.'
        : 'No strong malicious indicators were detected in the provided input.';

  return {
    version: '1.0',
    score,
    level,
    threatType,
    explanation,
    factors: normalizedFactors,
    topDrivers: normalizedFactors.slice(0, 3).map((factor) => factor.label)
  };
}

function scoreText(text) {
  const lower = text.toLowerCase();
  const rules = [
    {
      id: 'weak-auth',
      label: 'Weak authentication patterns',
      regex: /password|login|credential|otp|mfa/gi,
      weight: 6,
      maxContribution: 24,
      severity: 'medium'
    },
    {
      id: 'injection-risk',
      label: 'Injection risk',
      regex: /select\s+\*|union\s+select|eval\(|exec\(|command injection|sql/gi,
      weight: 9,
      maxContribution: 30,
      severity: 'high'
    },
    {
      id: 'sensitive-data',
      label: 'Sensitive data exposure',
      regex: /apikey|secret|token|private key|credentials?/gi,
      weight: 8,
      maxContribution: 28,
      severity: 'high'
    },
    {
      id: 'unsafe-transport',
      label: 'Unsafe transport or storage',
      regex: /http:\/\/|plain text|unencrypted|no tls|weak hash/gi,
      weight: 5,
      maxContribution: 20,
      severity: 'medium'
    },
    {
      id: 'suspicious-process',
      label: 'Suspicious process or file activity',
      regex: /powershell|cmd\.exe|rundll32|vbs|macro|autorun/gi,
      weight: 6,
      maxContribution: 24,
      severity: 'medium'
    }
  ];

  const scoredFindings = rules
    .map((rule) => {
      const matches = lower.match(rule.regex) || [];
      return matches.length
        ? {
            id: rule.id,
            title: rule.label,
            count: matches.length,
            severity: rule.severity,
            weight: rule.weight,
            contribution: Math.min(matches.length * rule.weight, rule.maxContribution)
          }
        : null;
    })
    .filter(Boolean);

  const findings = scoredFindings.map((finding) => ({
    title: finding.title,
    count: finding.count,
    severity: finding.severity
  }));

  const riskEngine = buildRiskEngine({
    baseline: 8,
    factors: scoredFindings
  });

  const riskScore = riskEngine.score;
  const riskLevel = riskEngine.level;
  const threatType = riskEngine.threatType;
  const explanation = riskEngine.explanation;

  const recommendationPool = {
    'Weak authentication patterns': 'Enforce MFA and remove weak authentication fallback flows.',
    'Injection risk': 'Apply strict input validation and parameterized query execution.',
    'Sensitive data exposure': 'Rotate leaked credentials and move secrets to a secure vault.',
    'Unsafe transport or storage': 'Require TLS in transit and encrypt sensitive data at rest.',
    'Suspicious process or file activity': 'Isolate affected endpoints and inspect process ancestry in EDR.'
  };

  const recommendations = riskEngine.topDrivers.length
    ? riskEngine.topDrivers.map((driver) => recommendationPool[driver]).filter(Boolean)
    : [];

  if (!recommendations.length) {
    recommendations.push('No critical remediation needed, continue monitoring and maintain baseline controls.');
  }

  return {
    findings,
    riskScore,
    riskLevel,
    threatType,
    explanation,
    recommendations,
    riskEngine
  };
}

function normalizeHashType(hashValue) {
  const value = String(hashValue || '').trim().toLowerCase();
  if (!value) {
    return 'unknown';
  }

  if (/^[a-f0-9]{32}$/.test(value)) {
    return 'md5';
  }

  if (/^[a-f0-9]{40}$/.test(value)) {
    return 'sha1';
  }

  if (/^[a-f0-9]{64}$/.test(value)) {
    return 'sha256';
  }

  if (/^[a-f0-9]{128}$/.test(value)) {
    return 'sha512';
  }

  return 'unknown';
}

function isPrivateIpv4(ip) {
  const octets = String(ip || '').split('.').map(Number);
  if (octets.length !== 4 || octets.some((value) => Number.isNaN(value) || value < 0 || value > 255)) {
    return false;
  }

  if (octets[0] === 10) return true;
  if (octets[0] === 127) return true;
  if (octets[0] === 192 && octets[1] === 168) return true;
  if (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) return true;
  return false;
}

function safeParseUrl(rawUrl) {
  try {
    return new URL(String(rawUrl || '').trim());
  } catch (error) {
    return null;
  }
}

function extractIocsFromText(text) {
  const source = String(text || '');
  const urlMatches = source.match(/https?:\/\/[^\s"'<>\])]+/gi) || [];
  const ipv4Matches = source.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
  const domainMatches = source.match(/\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,24}\b/g) || [];
  const hashMatches = source.match(/\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{128}\b/g) || [];

  const unique = {
    urls: [...new Set(urlMatches.map((item) => item.trim()))],
    ips: [...new Set(ipv4Matches.map((item) => item.trim()))],
    domains: [...new Set(domainMatches.map((item) => item.trim().toLowerCase()))],
    hashes: [...new Set(hashMatches.map((item) => item.trim().toLowerCase()))]
  };

  return unique;
}

function enrichIocs(iocs) {
  const suspiciousTldPattern = /\.(ru|tk|top|xyz|click|zip|mov)$/i;
  const shortenedUrlPattern = /(?:^|\.)((bit\.ly|tinyurl\.com|t\.co|ow\.ly|is\.gd|cutt\.ly))$/i;
  const credentialPathPattern = /login|verify|secure|update|signin|password/i;

  const urlIntel = (iocs.urls || []).map((rawUrl) => {
    const parsed = safeParseUrl(rawUrl);
    const host = parsed?.hostname?.toLowerCase() || null;
    const usesHttp = Boolean(parsed && parsed.protocol === 'http:');
    const suspiciousTld = Boolean(host && suspiciousTldPattern.test(host));
    const shortened = Boolean(host && shortenedUrlPattern.test(host));
    const suspiciousPath = Boolean(parsed && credentialPathPattern.test(`${parsed.pathname}${parsed.search}`));
    const risk = usesHttp || suspiciousTld || shortened || suspiciousPath ? 'high' : 'low';

    return {
      type: 'url',
      value: rawUrl,
      confidence: risk === 'high' ? 0.86 : 0.42,
      tags: [
        usesHttp ? 'insecure-transport' : null,
        suspiciousTld ? 'suspicious-tld' : null,
        shortened ? 'url-shortener' : null,
        suspiciousPath ? 'credential-lure' : null
      ].filter(Boolean)
    };
  });

  const ipIntel = (iocs.ips || []).map((ipValue) => {
    const privateIp = isPrivateIpv4(ipValue);
    return {
      type: 'ip',
      value: ipValue,
      confidence: privateIp ? 0.2 : 0.65,
      tags: [privateIp ? 'private-range' : 'public-ip']
    };
  });

  const domainIntel = (iocs.domains || []).map((domainValue) => {
    const suspiciousTld = suspiciousTldPattern.test(domainValue);
    const shortened = shortenedUrlPattern.test(domainValue);
    return {
      type: 'domain',
      value: domainValue,
      confidence: suspiciousTld || shortened ? 0.78 : 0.34,
      tags: [
        suspiciousTld ? 'suspicious-tld' : null,
        shortened ? 'url-shortener' : null
      ].filter(Boolean)
    };
  });

  const hashIntel = (iocs.hashes || []).map((hashValue) => ({
    type: 'hash',
    value: hashValue,
    confidence: 0.7,
    tags: [normalizeHashType(hashValue)]
  }));

  const indicators = [...urlIntel, ...ipIntel, ...domainIntel, ...hashIntel];
  const highConfidenceCount = indicators.filter((indicator) => indicator.confidence >= 0.75).length;

  return {
    counts: {
      urls: (iocs.urls || []).length,
      ips: (iocs.ips || []).length,
      domains: (iocs.domains || []).length,
      hashes: (iocs.hashes || []).length,
      total: indicators.length
    },
    highConfidenceCount,
    indicators
  };
}

function scoreUrl(urlValue) {
  const normalizedUrl = String(urlValue || '').trim();

  let parsedUrl;
  try {
    parsedUrl = new URL(normalizedUrl);
  } catch (error) {
    return {
      findings: [{ title: 'Invalid URL format', count: 1, severity: 'high' }],
      riskScore: 90,
      riskLevel: 'High',
      recommendations: ['Verify the URL format before visiting it.']
    };
  }

  const host = parsedUrl.hostname.toLowerCase();
  const path = parsedUrl.pathname.toLowerCase();
  const query = parsedUrl.search.toLowerCase();
  const urlText = `${host}${path}${query}`;

  const rules = [
    { id: 'host-ip', label: 'IP address in host', regex: /(?:\d{1,3}\.){3}\d{1,3}/, weight: 26, severity: 'high' },
    { id: 'url-shortener', label: 'Shortened URL service', regex: /bit\.ly|tinyurl|t\.co|ow\.ly|is\.gd|cutt\.ly/, weight: 24, severity: 'high' },
    { id: 'credential-lure', label: 'Credential harvesting keywords', regex: /login|verify|secure|update|account|signin|password/, weight: 20, severity: 'high' },
    { id: 'suspicious-tld', label: 'Suspicious TLD', regex: /\.(ru|tk|top|xyz|click|zip|mov)$/, weight: 18, severity: 'medium' },
    { id: 'long-path', label: 'Long or complex path', regex: /\/.{60,}/, weight: 10, severity: 'low' }
  ];

  const scoredFindings = rules
    .map((rule) => {
      const matched = rule.regex.test(urlText);
      rule.regex.lastIndex = 0;
      return matched
        ? {
            id: rule.id,
            title: rule.label,
            count: 1,
            severity: rule.severity,
            weight: rule.weight,
            contribution: rule.weight
          }
        : null;
    })
    .filter(Boolean);

  const findings = scoredFindings.map((finding) => ({
    title: finding.title,
    count: finding.count,
    severity: finding.severity
  }));

  const riskEngine = buildRiskEngine({ baseline: 10, factors: scoredFindings });

  const riskScore = riskEngine.score;
  const riskLevel = riskEngine.level;
  const threatType = riskEngine.threatType;
  const explanation = riskEngine.explanation;

  return {
    findings,
    riskScore,
    riskLevel,
    threatType,
    explanation,
    recommendations: [
      'Check the domain carefully before opening the link.',
      'Avoid entering credentials if the site is unexpected or newly registered.',
      'Use a safe browser or detonation environment for suspicious URLs.'
    ],
    riskEngine
  };
}

async function extractUploadText(file) {
  const filename = (file.originalname || '').toLowerCase();
  const mimetype = (file.mimetype || '').toLowerCase();

  if (mimetype === 'application/pdf' || filename.endsWith('.pdf')) {
    const parsed = await pdfParse(file.buffer);
    return parsed.text || '';
  }

  return file.buffer.toString('utf8');
}

async function storeArtifact(client, userId, file) {
  const bucket = process.env.SUPABASE_STORAGE_BUCKET || storageBucket;
  if (!bucket) {
    return null;
  }

  const safeName = String(file.originalname || 'upload.bin').replace(/[^a-zA-Z0-9._-]/g, '_');
  const artifactPath = `${userId || 'anonymous'}/${Date.now()}-${safeName}`;
  const { error } = await client.storage.from(bucket).upload(artifactPath, file.buffer, {
    contentType: file.mimetype || 'application/octet-stream',
    upsert: false
  });

  if (error) {
    return null;
  }

  return artifactPath;
}

async function persistReport(client, payload) {
  const fullInsertPayload = {
    user_id: payload.userId,
    title: payload.title,
    summary: payload.summary,
    findings: payload.findings,
    recommendations: payload.recommendations,
    source_type: payload.sourceType,
    source_value: payload.sourceValue,
    artifact_path: payload.artifactPath || null,
    metadata: payload.metadata || {}
  };

  const fullSelect = 'id, user_id, title, summary, findings, recommendations, source_type, source_value, artifact_path, metadata, created_at';
  const metadataFallbackSelect = 'id, user_id, title, summary, findings, recommendations, metadata, created_at';
  const basicSelect = 'id, user_id, title, summary, findings, recommendations, created_at';

  let { data, error } = await client
    .from('reports')
    .insert(fullInsertPayload)
    .select(fullSelect)
    .single();

  if (error && /schema cache|column/i.test(error.message || '')) {
    const metadataFallbackInsertPayload = {
      user_id: payload.userId,
      title: payload.title,
      summary: payload.summary,
      findings: payload.findings,
      recommendations: payload.recommendations,
      metadata: payload.metadata || {}
    };

    const metadataFallbackResult = await client
      .from('reports')
      .insert(metadataFallbackInsertPayload)
      .select(metadataFallbackSelect)
      .single();

    data = metadataFallbackResult.data;
    error = metadataFallbackResult.error;
  }

  if (error && /schema cache|column/i.test(error.message || '')) {
    const basicFallbackInsertPayload = {
      user_id: payload.userId,
      title: payload.title,
      summary: payload.summary,
      findings: payload.findings,
      recommendations: payload.recommendations
    };

    const basicFallbackResult = await client
      .from('reports')
      .insert(basicFallbackInsertPayload)
      .select(basicSelect)
      .single();

    data = basicFallbackResult.data;
    error = basicFallbackResult.error;
  }

  if (error) {
    throw new Error(error.message);
  }

  return data;
}

function parseReportsListFilters(query) {
  const q = String(query.q || '').trim();
  const sourceType = String(query.sourceType || '').trim().toLowerCase();
  const risk = String(query.risk || '').trim().toLowerCase();
  const reportId = String(query.reportId || '').trim();
  const iocType = String(query.iocType || '').trim().toLowerCase();

  const limitRaw = Number(query.limit);
  const offsetRaw = Number(query.offset);

  const limit = Number.isFinite(limitRaw) ? Math.min(Math.max(Math.floor(limitRaw), 1), 100) : 20;
  const offset = Number.isFinite(offsetRaw) ? Math.max(Math.floor(offsetRaw), 0) : 0;

  return {
    q,
    sourceType: ['text', 'url', 'upload'].includes(sourceType) ? sourceType : null,
    risk: ['high', 'moderate', 'low'].includes(risk) ? risk : null,
    reportId: reportId || null,
    iocType: ['urls', 'ips', 'domains', 'hashes'].includes(iocType) ? iocType : null,
    limit,
    offset
  };
}

function applyReportFilters(queryBuilder, filters, options = {}) {
  const includeSourceValue = options.includeSourceValue !== false;
  const includeMetadata = options.includeMetadata !== false;
  let query = queryBuilder;

  if (filters.reportId) {
    query = query.eq('id', filters.reportId);
  }

  if (filters.sourceType) {
    query = query.eq('source_type', filters.sourceType);
  }

  if (filters.risk) {
    const desiredRisk = `${filters.risk.charAt(0).toUpperCase()}${filters.risk.slice(1)}`;
    query = query.ilike('summary', `Risk level: ${desiredRisk}%`);
  }

  if (filters.q) {
    const sanitized = filters.q.replace(/[%_,]/g, ' ').trim();
    if (sanitized) {
      const searchableFields = [`title.ilike.%${sanitized}%`, `summary.ilike.%${sanitized}%`];

      if (includeSourceValue) {
        searchableFields.push(`source_value.ilike.%${sanitized}%`);
      }

      query = query.or(searchableFields.join(','));
    }
  }

  if (filters.iocType && includeMetadata) {
    query = query.filter(`metadata->iocIntel->counts->>${filters.iocType}`, 'gt', '0');
  }

  return query;
}

function getRiskProfileFromReport(report) {
  const level = String(report?.metadata?.riskEngine?.level || '').trim();
  const score = Number(report?.metadata?.riskEngine?.score);

  if (level) {
    return {
      level,
      score: Number.isFinite(score) ? Math.round(score) : null,
      explanation: String(report?.metadata?.riskEngine?.explanation || '').trim() || null
    };
  }

  const summary = String(report?.summary || '');
  const levelMatch = summary.match(/Risk\s*level:\s*(High|Moderate|Low)/i);
  const scoreMatch = summary.match(/\((\d+)\/100\)/i);

  return {
    level: levelMatch ? levelMatch[1] : 'Unknown',
    score: scoreMatch ? Number(scoreMatch[1]) : null,
    explanation: null
  };
}

function sanitizeFilename(value) {
  return String(value || 'report')
    .replace(/[^a-z0-9._-]+/gi, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 80) || 'report';
}

function writePdfLine(doc, text, options = {}) {
  const maxY = 760;
  if (doc.y > maxY) {
    doc.addPage();
  }

  doc
    .font(options.font || 'Helvetica')
    .fontSize(options.size || 11)
    .fillColor(options.color || '#1b1f24')
    .text(String(text || ''), {
      width: 500,
      lineGap: options.lineGap || 2
    });
}

function writePdfSectionTitle(doc, title) {
  if (doc.y > 730) {
    doc.addPage();
  }

  doc.moveDown(0.7);
  doc
    .font('Helvetica-Bold')
    .fontSize(13)
    .fillColor('#0d2d54')
    .text(String(title || ''));
  doc.moveDown(0.2);
}

function resolveBrandLogoPath() {
  const envLogo = String(process.env.REPORT_BRAND_LOGO_PATH || '').trim();
  const candidatePaths = [
    envLogo ? path.resolve(__dirname, '../../', envLogo) : null,
    path.resolve(__dirname, '../../social-preview.png'),
    path.resolve(__dirname, '../../favicon.svg')
  ].filter(Boolean);

  return candidatePaths.find((candidate) => {
    try {
      return fs.existsSync(candidate);
    } catch (error) {
      return false;
    }
  }) || null;
}

function drawBrandedHeader(doc, reportTitle, mode = 'full') {
  const brandPrimary = process.env.REPORT_BRAND_PRIMARY || '#0c1f3f';
  const brandAccent = process.env.REPORT_BRAND_ACCENT || '#24d08d';
  const brandName = process.env.REPORT_BRAND_NAME || 'AI Cyber Analyzer';
  const logoPath = resolveBrandLogoPath();

  // Premium header with solid background
  doc.rect(0, 0, doc.page.width, 110).fill(brandPrimary);
  
  // Elegant accent bar at bottom
  doc.rect(0, 108, doc.page.width, 3).fill(brandAccent);
  
  // Top accent stripe
  doc.rect(0, 0, doc.page.width, 6).fill(brandAccent);

  // Logo with professional spacing
  if (logoPath && /\.(png|jpg|jpeg)$/i.test(logoPath)) {
    try {
      doc.image(logoPath, 50, 20, { fit: [40, 40] });
    } catch (error) {
      // Ignore logo draw failures
    }
  }

  // Brand name - modern, clean typography
  doc
    .fillColor('#ffffff')
    .font('Helvetica-Bold')
    .fontSize(15)
    .text(brandName, 100, 22, { width: 360 });

  // Subtitle with accent color for visual interest
  doc
    .font('Helvetica')
    .fontSize(10)
    .fillColor(brandAccent)
    .text(mode === 'brief' ? 'Leadership Brief' : 'Executive Report', 100, 42);

  // Report title - premium styling
  doc.moveDown(1);
  doc
    .font('Helvetica-Bold')
    .fontSize(13)
    .fillColor('#f0f4f8')
    .text(String(reportTitle || 'Security Report'), 50, 68, {
      width: 500,
      ellipsis: true
    });

  doc.y = 125;
}

function deriveOrganizationName(user) {
  const envOrg = String(process.env.REPORT_ORGANIZATION_NAME || '').trim();
  if (envOrg) {
    return envOrg;
  }

  const email = String(user?.email || '').trim().toLowerCase();
  if (email.includes('@')) {
    const domain = email.split('@')[1] || '';
    const root = domain.split('.')[0] || '';
    if (root) {
      return root.charAt(0).toUpperCase() + root.slice(1);
    }
  }

  return 'AI Cyber Analyzer';
}

function drawWatermark(doc, text) {
  const label = String(text || '').trim();
  if (!label || label.toLowerCase() === 'none') {
    return;
  }

  const previousY = doc.y;

  const centerX = doc.page.width / 2;
  const centerY = doc.page.height / 2;

  doc.save();
  doc.rotate(-35, { origin: [centerX, centerY] });
  doc.fillColor('#94a3b8', 0.14);
  doc.font('Helvetica-Bold').fontSize(56).text(label.toUpperCase(), 70, centerY - 30, {
    width: doc.page.width - 140,
    align: 'center'
  });
  doc.restore();
  doc.y = previousY;
}

function drawFooter(doc, context = {}) {
  const previousY = doc.y;
  const generatedAt = context.generatedAt || new Date().toLocaleString();
  const classColor = context.classification === 'Confidential' ? '#dc2626' : context.classification === 'Internal' ? '#f59e0b' : '#16a34a';

  // Premium footer background
  doc.rect(0, doc.page.height - 35, doc.page.width, 35).fill('#f5f7fa');
  
  // Divider line
  doc.moveTo(50, doc.page.height - 35).lineTo(doc.page.width - 50, doc.page.height - 35).stroke('#e2e8f0');

  // Left side - Organization info
  const leftText = [
    context.organizationName || 'AI Cyber Analyzer',
    context.generatedBy ? `${context.generatedBy}` : null
  ].filter(Boolean).join(' • ');

  doc
    .font('Helvetica')
    .fontSize(8)
    .fillColor('#64748b')
    .text(leftText, 50, doc.page.height - 29, {
      width: 320,
      align: 'left'
    });

  // Center - Classification badge
  doc
    .font('Helvetica-Bold')
    .fontSize(8)
    .fillColor(classColor)
    .text(`[${context.classification || 'UNCLASSIFIED'}]`, doc.page.width / 2 - 40, doc.page.height - 29, {
      width: 80,
      align: 'center'
    });

  // Right side - Report info and timestamp
  const rightText = [
    context.reportId ? `ID: ${context.reportId.slice(0, 8)}...` : null,
    generatedAt.split(' ')[0] // Date only to save space
  ].filter(Boolean).join(' • ');

  doc
    .font('Helvetica')
    .fontSize(8)
    .fillColor('#64748b')
    .text(rightText, doc.page.width - 270, doc.page.height - 29, {
      width: 220,
      align: 'right'
    });

  doc.y = previousY;
}

function renderFullReportCoverPage(doc, payload) {
  const brandPrimary = process.env.REPORT_BRAND_PRIMARY || '#0c1f3f';
  const brandAccent = process.env.REPORT_BRAND_ACCENT || '#24d08d';
  const logoPath = resolveBrandLogoPath();

  // Premium gradient-like background with layered design
  doc.rect(0, 0, doc.page.width, doc.page.height).fill('#f5f7fa');
  
  // Top section with premium dark background
  doc.rect(0, 0, doc.page.width, 240).fill(brandPrimary);
  
  // Accent bar - elegant thin line
  doc.rect(0, 238, doc.page.width, 2).fill(brandAccent);
  
  // Decorative corner accent
  doc.rect(0, 0, doc.page.width, 12).fill(brandAccent);

  // Logo area with elegant spacing
  if (logoPath && /\.(png|jpg|jpeg)$/i.test(logoPath)) {
    try {
      doc.image(logoPath, 50, 30, { fit: [56, 56] });
    } catch (error) {
      // Icon fallback
    }
  }

  // Organization name with modern styling
  doc
    .font('Helvetica-Bold')
    .fontSize(18)
    .fillColor('#ffffff')
    .text(payload.organizationName || 'AI Cyber Analyzer', 120, 34, { width: 350 });

  // Tagline with accent color
  doc
    .font('Helvetica')
    .fontSize(12)
    .fillColor(brandAccent)
    .text('Executive Cybersecurity Report', 120, 58);

  // Main title - premium styling with proper spacing
  doc.moveDown(3.5);
  doc
    .font('Helvetica-Bold')
    .fontSize(32)
    .fillColor('#0f172a')
    .text(String(payload.title || 'Untitled report'), 50, 290, {
      width: 500,
      ellipsis: true
    });

  // Risk badge with color coding
  const riskColor = payload.riskLabel.includes('High') ? '#dc2626' : payload.riskLabel.includes('Moderate') ? '#f59e0b' : '#16a34a';
  doc.rect(50, 350, 180, 36).fill('#f9fafb').stroke(riskColor);
  doc
    .font('Helvetica-Bold')
    .fontSize(11)
    .fillColor('#64748b')
    .text('Risk Posture', 58, 357);
  doc
    .font('Helvetica-Bold')
    .fontSize(14)
    .fillColor(riskColor)
    .text(payload.riskLabel, 58, 372);

  // Classification badge
  const classColor = payload.classification === 'Confidential' ? '#dc2626' : payload.classification === 'Internal' ? '#f59e0b' : '#16a34a';
  doc.rect(250, 350, 180, 36).fill('#f9fafb').stroke(classColor);
  doc
    .font('Helvetica-Bold')
    .fontSize(11)
    .fillColor('#64748b')
    .text('Classification', 258, 357);
  doc
    .font('Helvetica-Bold')
    .fontSize(14)
    .fillColor(classColor)
    .text(payload.classification, 258, 372);

  // Divider line
  doc.moveTo(50, 420).lineTo(550, 420).stroke('#e2e8f0').dash(3, { space: 2 });

  // Metadata section with professional layout
  doc.moveDown(2);
  const metadataProps = [
    { label: 'Prepared for', value: payload.organizationName },
    { label: 'Generated by', value: payload.generatedBy },
    { label: 'Created', value: payload.createdAtLabel },
    { label: 'Report ID', value: payload.reportId }
  ];

  metadataProps.forEach((prop, index) => {
    const y = 440 + (index * 22);
    doc
      .font('Helvetica-Bold')
      .fontSize(10)
      .fillColor('#64748b')
      .text(prop.label, 50, y);
    doc
      .font('Helvetica')
      .fontSize(10)
      .fillColor('#0f172a')
      .text(prop.value, 150, y, { width: 400 });
  });

  // Bottom disclaimer with elegant styling
  doc.rect(0, doc.page.height - 80, doc.page.width, 80).fill('#f9fafb');
  doc
    .font('Helvetica')
    .fontSize(9)
    .fillColor('#64748b')
    .text('CONFIDENTIAL NOTICE', 50, doc.page.height - 70, { width: 500 });
  doc
    .font('Helvetica')
    .fontSize(8.5)
    .fillColor('#64748b')
    .text('This document contains sensitive security analysis and must be handled according to your organization\'s information security policies.', 50, doc.page.height - 53, {
      width: 500,
      lineGap: 2
    });
}

function summarizeExecutiveNarrative(mappedReport, risk, topMitre) {
  const riskLabel = `${risk.level}${Number.isFinite(risk.score) ? ` (${risk.score}/100)` : ''}`;
  const topTechnique = topMitre[0] ? `${topMitre[0].id} ${topMitre[0].name}` : 'No dominant MITRE technique detected';
  const topDrivers = Array.isArray(mappedReport.metadata?.riskEngine?.topDrivers)
    ? mappedReport.metadata.riskEngine.topDrivers.slice(0, 2).join(' and ')
    : '';

  const driverSummary = topDrivers ? `Primary risk drivers include ${topDrivers}.` : 'No dominant risk drivers were recorded.';

  return `${mappedReport.title || 'This report'} is currently assessed as ${riskLabel}. ${driverSummary} The strongest mapped attacker behavior is ${topTechnique}.`;
}

function renderBriefOnePage(doc, mappedReport, risk, iocCounts, topMitre) {
  const brandAccent = process.env.REPORT_BRAND_ACCENT || '#24d08d';
  
  // Premium section header styling function
  const writeSection = (title) => {
    doc.moveDown(0.3);
    doc.rect(50, doc.y, 500, 26).fill('#f0f4f8').stroke(brandAccent);
    doc
      .font('Helvetica-Bold')
      .fontSize(12)
      .fillColor('#0c1f3f')
      .text(title, 56, doc.y + 6, { width: 480 });
    doc.moveDown(1.5);
  };

  // Executive Summary
  writeSection('Executive Summary');
  doc
    .font('Helvetica')
    .fontSize(10)
    .fillColor('#1f2937')
    .text(summarizeExecutiveNarrative(mappedReport, risk, topMitre), {
      width: 500,
      lineGap: 3
    });
  doc
    .fontSize(10)
    .text(risk.explanation || mappedReport.summary || 'No additional explanation available.', {
      width: 500,
      lineGap: 3
    });

  // Key Metrics - dashboard style
  writeSection('Key Metrics');
  
  // Create a mini metrics grid
  const metricsY = doc.y;
  const colWidth = 160;
  
  // Metric 1: Risk Level
  const riskColor = risk.level === 'High' ? '#dc2626' : risk.level === 'Moderate' ? '#f59e0b' : '#16a34a';
  doc.rect(50, metricsY, colWidth - 10, 32).fill('#f9fafb').stroke(riskColor);
  doc
    .font('Helvetica-Bold')
    .fontSize(9)
    .fillColor('#64748b')
    .text('Risk Level', 56, metricsY + 6);
  doc
    .font('Helvetica-Bold')
    .fontSize(13)
    .fillColor(riskColor)
    .text(`${risk.level}${Number.isFinite(risk.score) ? ` (${risk.score}/100)` : ''}`, 56, metricsY + 16);

  // Metric 2: Indicators
  doc.rect(50 + colWidth, metricsY, colWidth - 10, 32).fill('#f9fafb').stroke(brandAccent);
  doc
    .font('Helvetica-Bold')
    .fontSize(9)
    .fillColor('#64748b')
    .text('Indicators', 56 + colWidth, metricsY + 6);
  doc
    .font('Helvetica-Bold')
    .fontSize(13)
    .fillColor(brandAccent)
    .text(`${Number(iocCounts.total || 0)}`, 56 + colWidth, metricsY + 16);

  // Metric 3: High-Confidence
  doc.rect(50 + colWidth * 2, metricsY, colWidth - 10, 32).fill('#f9fafb').stroke('#8b5cf6');
  doc
    .font('Helvetica-Bold')
    .fontSize(9)
    .fillColor('#64748b')
    .text('High-Conf', 56 + colWidth * 2, metricsY + 6);
  doc
    .font('Helvetica-Bold')
    .fontSize(13)
    .fillColor('#8b5cf6')
    .text(`${Number(mappedReport.metadata?.iocIntel?.highConfidenceCount || 0)}`, 56 + colWidth * 2, metricsY + 16);

  doc.moveDown(2);

  // MITRE Techniques
  writeSection('Top MITRE Techniques');
  if (!topMitre.length) {
    doc
      .font('Helvetica')
      .fontSize(10)
      .fillColor('#6b7280')
      .text('No MITRE techniques were mapped for this report.');
  } else {
    topMitre.slice(0, 3).forEach((technique, index) => {
      const techColor = technique.severity === 'High' ? '#dc2626' : technique.severity === 'Medium' ? '#f59e0b' : '#3b82f6';
      doc
        .font('Helvetica-Bold')
        .fontSize(9.5)
        .fillColor('#0c1f3f')
        .text(`${index + 1}. ${technique.id || 'Unknown'}`, 50);
      doc
        .font('Helvetica')
        .fontSize(9)
        .fillColor('#4b5563')
        .text(`${technique.name || 'Unknown'} • ${techColor} Severity • ${Math.round(Number(technique.confidence || 0) * 100)}% Confidence`, {
          width: 500,
          indent: 10
        });
    });
  }

  doc.moveDown(0.5);

  // Immediate Actions
  writeSection('Immediate Actions');
  const actions = (Array.isArray(mappedReport.recommendations) ? mappedReport.recommendations : []).slice(0, 3);
  if (!actions.length) {
    doc
      .font('Helvetica')
      .fontSize(10)
      .fillColor('#6b7280')
      .text('No immediate actions recorded. Continue baseline monitoring.');
  } else {
    actions.forEach((item, index) => {
      doc
        .font('Helvetica-Bold')
        .fontSize(9.5)
        .fillColor('#0c1f3f')
        .text(`${index + 1}. ${item}`, {
          width: 500,
          indent: 0
        });
    });
  }
}

function renderFullExecutiveReport(doc, mappedReport, risk, iocCounts, topMitre) {
  const brandAccent = process.env.REPORT_BRAND_ACCENT || '#24d08d';
  
  // Premium section header function
  const writeSection = (title) => {
    doc.moveDown(0.2);
    if (doc.y > 700) doc.addPage();
    doc.rect(50, doc.y, 500, 24).fill('#f0f4f8').stroke(brandAccent);
    doc
      .font('Helvetica-Bold')
      .fontSize(11)
      .fillColor('#0c1f3f')
      .text(title, 56, doc.y + 5, { width: 480 });
    doc.moveDown(1.2);
  };

  // Executive Summary
  writeSection('Executive Summary');
  doc
    .font('Helvetica')
    .fontSize(10)
    .fillColor('#1f2937')
    .text(summarizeExecutiveNarrative(mappedReport, risk, topMitre), {
      width: 500,
      lineGap: 2
    });
  doc.text(risk.explanation || mappedReport.summary || 'No additional risk explanation available.', {
    width: 500,
    lineGap: 2
  });

  // Risk Summary with visual indicators
  writeSection('Risk Assessment');
  const riskColor = risk.level === 'High' ? '#dc2626' : risk.level === 'Moderate' ? '#f59e0b' : '#16a34a';
  doc.rect(50, doc.y, 150, 28).fill('#f9fafb').stroke(riskColor);
  doc
    .font('Helvetica-Bold')
    .fontSize(9)
    .fillColor('#64748b')
    .text('Risk Level', 56, doc.y + 4);
  doc
    .font('Helvetica-Bold')
    .fontSize(12)
    .fillColor(riskColor)
    .text(`${risk.level}${Number.isFinite(risk.score) ? ` (${risk.score}/100)` : ''}`, 56, doc.y + 13);
  
  doc
    .font('Helvetica')
    .fontSize(9)
    .fillColor('#6b7280')
    .text(`Source: ${mappedReport.sourceType}${mappedReport.sourceValue ? ` - ${mappedReport.sourceValue}` : ''}`, 220, doc.y - 24, { width: 330 });

  doc.moveDown(2);

  // MITRE ATT&CK Techniques
  writeSection('Top MITRE ATT&CK Techniques');
  if (!topMitre.length) {
    doc
      .font('Helvetica')
      .fontSize(10)
      .fillColor('#6b7280')
      .text('No MITRE techniques were mapped for this report.');
  } else {
    topMitre.forEach((technique, index) => {
      const techColor = technique.severity === 'High' ? '#dc2626' : technique.severity === 'Medium' ? '#f59e0b' : '#3b82f6';
      
      // Technique header
      doc
        .font('Helvetica-Bold')
        .fontSize(10)
        .fillColor('#0c1f3f')
        .text(`${index + 1}. ${technique.id || 'Unknown'} - ${technique.name || 'Unknown'}`);
      
      // Technique details
      doc
        .font('Helvetica')
        .fontSize(9)
        .fillColor('#64748b')
        .text(`${technique.tactic || 'Unknown'} | ${techColor} Severity | ${Math.round(Number(technique.confidence || 0) * 100)}% Confidence`, {
          indent: 10
        });
      
      // Reasons
      if (Array.isArray(technique.reasons) && technique.reasons.length) {
        doc
          .font('Helvetica')
          .fontSize(8.5)
          .fillColor('#64748b')
          .text(`Evidence: ${technique.reasons.slice(0, 2).join('; ')}`, {
            indent: 10,
            width: 480
          });
      }
      doc.moveDown(0.3);
    });
  }

  // Technical Appendix
  writeSection('Technical Appendix');
  
  // IOC Statistics with visual layout
  doc
    .font('Helvetica-Bold')
    .fontSize(10)
    .fillColor('#0c1f3f')
    .text('Indicator of Compromise (IOC) Statistics');
  doc.moveDown(0.2);
  
  const iocMetrics = [
    { label: 'Total', value: iocCounts.total || 0, color: brandAccent },
    { label: 'URLs', value: iocCounts.urls || 0, color: '#3b82f6' },
    { label: 'IPs', value: iocCounts.ips || 0, color: '#f59e0b' },
    { label: 'Domains', value: iocCounts.domains || 0, color: '#8b5cf6' },
    { label: 'Hashes', value: iocCounts.hashes || 0, color: '#ec4899' }
  ];
  
  let metricsY = doc.y;
  iocMetrics.forEach((metric, i) => {
    if (i % 3 === 0 && i > 0) {
      metricsY += 30;
      doc.y = metricsY;
    }
    const x = 50 + (i % 3) * 160;
    const y = metricsY;
    doc.rect(x, y, 150, 26).fill('#f9fafb').stroke(metric.color);
    doc
      .font('Helvetica-Bold')
      .fontSize(8)
      .fillColor('#64748b')
      .text(metric.label, x + 6, y + 4);
    doc
      .font('Helvetica-Bold')
      .fontSize(11)
      .fillColor(metric.color)
      .text(String(metric.value), x + 6, y + 13);
  });
  
  doc.y = metricsY + 30;
  doc
    .font('Helvetica')
    .fontSize(9)
    .fillColor('#64748b')
    .text(`High-confidence indicators: ${Number(mappedReport.metadata?.iocIntel?.highConfidenceCount || 0)}`);

  doc.moveDown(0.8);

  // Recommendations
  writeSection('Recommended Actions');
  if (!Array.isArray(mappedReport.recommendations) || !mappedReport.recommendations.length) {
    doc
      .font('Helvetica')
      .fontSize(10)
      .fillColor('#6b7280')
      .text('No recommendations were provided for this report.');
  } else {
    mappedReport.recommendations.slice(0, 8).forEach((item, index) => {
      doc
        .font('Helvetica-Bold')
        .fontSize(9.5)
        .fillColor('#0c1f3f')
        .text(`${index + 1}. ${item}`, {
          width: 500,
          indent: 0
        });
    });
  }

  // Findings
  writeSection('Detailed Findings');
  if (!Array.isArray(mappedReport.findings) || !mappedReport.findings.length) {
    doc
      .font('Helvetica')
      .fontSize(10)
      .fillColor('#6b7280')
      .text('No findings were recorded.');
  } else {
    mappedReport.findings.slice(0, 15).forEach((finding, index) => {
      const severityColor = finding.severity === 'High' ? '#dc2626' : finding.severity === 'Medium' ? '#f59e0b' : '#3b82f6';
      doc
        .font('Helvetica-Bold')
        .fontSize(9.5)
        .fillColor('#0c1f3f')
        .text(`${index + 1}. ${finding.title || 'Untitled'}`);
      doc
        .font('Helvetica')
        .fontSize(9)
        .fillColor(severityColor)
        .text(`${finding.severity || 'unknown'} • Count: ${finding.count || 0}`, {
          indent: 10
        });
    });
  }
}

function getPdfWatermarkConfig() {
  const configured = String(process.env.REPORT_WATERMARK_TEXT || '').trim();
  const defaultClassification = String(process.env.REPORT_CLASSIFICATION || 'Confidential').trim();

  if (!configured) {
    return {
      source: 'classification',
      text: null,
      effectiveFromClassification: true,
      defaultClassification
    };
  }

  if (configured.toLowerCase() === 'none') {
    return {
      source: 'disabled',
      text: configured,
      effectiveFromClassification: false,
      defaultClassification
    };
  }

  return {
    source: 'override',
    text: configured,
    effectiveFromClassification: false,
    defaultClassification
  };
}

async function fetchReportById(client, reportId, userId) {
  const fullSelect = 'id, user_id, title, summary, findings, recommendations, source_type, source_value, artifact_path, metadata, created_at';
  const metadataFallbackSelect = 'id, user_id, title, summary, findings, recommendations, metadata, created_at';
  const basicSelect = 'id, user_id, title, summary, findings, recommendations, created_at';

  let query = client
    .from('reports')
    .select(fullSelect)
    .eq('id', reportId);

  if (userId) {
    query = query.eq('user_id', userId);
  }

  let { data, error } = await query.maybeSingle();

  if (error && /schema cache|column/i.test(error.message || '')) {
    let metadataFallbackQuery = client
      .from('reports')
      .select(metadataFallbackSelect)
      .eq('id', reportId);

    if (userId) {
      metadataFallbackQuery = metadataFallbackQuery.eq('user_id', userId);
    }

    const metadataFallbackResult = await metadataFallbackQuery.maybeSingle();
    data = metadataFallbackResult.data;
    error = metadataFallbackResult.error;
  }

  if (error && /schema cache|column/i.test(error.message || '')) {
    let basicFallbackQuery = client
      .from('reports')
      .select(basicSelect)
      .eq('id', reportId);

    if (userId) {
      basicFallbackQuery = basicFallbackQuery.eq('user_id', userId);
    }

    const basicFallbackResult = await basicFallbackQuery.maybeSingle();
    data = basicFallbackResult.data;
    error = basicFallbackResult.error;
  }

  if (error) {
    throw new Error(error.message);
  }

  return data;
}

exports.analyze = async (req, res) => {
  const { text, title } = req.body;
  const client = getSupabaseOrFail(res);

  if (!client) {
    return;
  }

  if (!text || !text.trim()) {
    return res.status(400).json({ message: 'Text is required for analysis' });
  }

  const analysis = scoreText(text);
  const iocs = extractIocsFromText(text);
  let iocIntel = enrichIocs(iocs);
  iocIntel = await enrichIocsWithThreatIntel(iocIntel);
  const mitreAttack = mapMitreAttack({ findings: analysis.findings, iocIntel, riskEngine: analysis.riskEngine });

  let savedReport;
  try {
    savedReport = await persistReport(client, {
      userId: req.user?.id || 'anonymous',
      title: title || 'Untitled analysis',
      summary: `Risk level: ${analysis.riskLevel} (${analysis.riskScore}/100)`,
      findings: analysis.findings,
      recommendations: analysis.recommendations,
      sourceType: 'text',
      sourceValue: (title || 'Untitled analysis').slice(0, 180),
      metadata: {
        inputLength: text.length,
        riskEngine: analysis.riskEngine,
        iocs,
        iocIntel,
        mitreAttack
      }
    });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }

  return res.json({
    message: 'Analysis complete',
    report: {
      id: savedReport.id,
      userId: savedReport.user_id,
      title: savedReport.title,
      summary: savedReport.summary,
      findings: savedReport.findings,
      recommendations: savedReport.recommendations,
      sourceType: savedReport.source_type || 'text',
      sourceValue: savedReport.source_value || null,
      artifactPath: savedReport.artifact_path || null,
      metadata: savedReport.metadata || {},
      createdAt: savedReport.created_at
    },
    analysis: {
      ...analysis,
      iocs,
      iocIntel,
      mitreAttack
    }
  });
};

exports.scanUrl = async (req, res) => {
  const { url, title } = req.body;
  const client = getSupabaseOrFail(res);

  if (!client) {
    return;
  }

  if (!url || !String(url).trim()) {
    return res.status(400).json({ message: 'URL is required for analysis' });
  }

  const analysis = scoreUrl(url);
  const iocs = extractIocsFromText(url);
  let iocIntel = enrichIocs(iocs);
  iocIntel = await enrichIocsWithThreatIntel(iocIntel);
  const mitreAttack = mapMitreAttack({ findings: analysis.findings, iocIntel, riskEngine: analysis.riskEngine });

  let savedReport;
  try {
    savedReport = await persistReport(client, {
      userId: req.user?.id || 'anonymous',
      title: title || 'URL scan',
      summary: `Risk level: ${analysis.riskLevel} (${analysis.riskScore}/100)`,
      findings: analysis.findings,
      recommendations: analysis.recommendations,
      sourceType: 'url',
      sourceValue: String(url).trim(),
      metadata: {
        hostname: (() => {
        try {
          return new URL(String(url).trim()).hostname;
        } catch (error) {
          return null;
        }
        })(),
        riskEngine: analysis.riskEngine,
        iocs,
        iocIntel,
        mitreAttack
      }
    });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }

  return res.json({
    message: 'URL scan complete',
    report: {
      id: savedReport.id,
      userId: savedReport.user_id,
      title: savedReport.title,
      summary: savedReport.summary,
      findings: savedReport.findings,
      recommendations: savedReport.recommendations,
      sourceType: savedReport.source_type || 'url',
      sourceValue: savedReport.source_value || String(url).trim(),
      artifactPath: savedReport.artifact_path || null,
      metadata: savedReport.metadata || {},
      createdAt: savedReport.created_at
    },
    analysis: {
      ...analysis,
      iocs,
      iocIntel,
      mitreAttack
    }
  });
};

exports.uploadAndAnalyze = async (req, res) => {
  const client = getSupabaseOrFail(res);

  if (!client) {
    return;
  }

  if (!req.file) {
    return res.status(400).json({ message: 'A file is required for upload analysis' });
  }

  const title = req.body.title || req.file.originalname || 'File scan';

  let extractedText = '';
  try {
    extractedText = await extractUploadText(req.file);
  } catch (error) {
    return res.status(400).json({ message: `Unable to read file contents: ${error.message}` });
  }

  const textForAnalysis = extractedText || req.file.originalname || '';
  const analysis = scoreText(textForAnalysis);
  const iocs = extractIocsFromText(textForAnalysis);
  let iocIntel = enrichIocs(iocs);
  iocIntel = await enrichIocsWithThreatIntel(iocIntel);
  const mitreAttack = mapMitreAttack({ findings: analysis.findings, iocIntel, riskEngine: analysis.riskEngine });
  const artifactPath = await storeArtifact(client, req.user?.id || 'anonymous', req.file);

  let savedReport;
  try {
    savedReport = await persistReport(client, {
      userId: req.user?.id || 'anonymous',
      title,
      summary: `Risk level: ${analysis.riskLevel} (${analysis.riskScore}/100)`,
      findings: analysis.findings,
      recommendations: analysis.recommendations,
      sourceType: 'upload',
      sourceValue: req.file.originalname,
      artifactPath,
      metadata: {
        fileName: req.file.originalname,
        fileType: req.file.mimetype,
        fileSize: req.file.size,
        extractedLength: extractedText.length,
        riskEngine: analysis.riskEngine,
        iocs,
        iocIntel,
        mitreAttack
      }
    });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }

  return res.json({
    message: 'File analysis complete',
    artifactStored: Boolean(artifactPath),
    report: {
      id: savedReport.id,
      userId: savedReport.user_id,
      title: savedReport.title,
      summary: savedReport.summary,
      findings: savedReport.findings,
      recommendations: savedReport.recommendations,
      sourceType: savedReport.source_type || 'upload',
      sourceValue: savedReport.source_value || req.file.originalname,
      artifactPath: savedReport.artifact_path || null,
      metadata: savedReport.metadata || {},
      createdAt: savedReport.created_at
    },
    analysis: {
      ...analysis,
      iocs,
      iocIntel,
      mitreAttack
    }
  });
};

exports.listReports = async (req, res) => {
  const client = getSupabaseOrFail(res);

  if (!client) {
    return;
  }

  const fullSelect = 'id, user_id, title, summary, findings, recommendations, source_type, source_value, artifact_path, metadata, created_at';
  const basicSelect = 'id, user_id, title, summary, findings, recommendations, created_at';
  const filters = parseReportsListFilters(req.query || {});

  let query = client
    .from('reports')
    .select(fullSelect, { count: 'exact' })
    .order('created_at', { ascending: false })
    .range(filters.offset, filters.offset + filters.limit - 1);

  if (req.user?.id) {
    query = query.eq('user_id', req.user.id);
  }

  query = applyReportFilters(query, filters);

  let { data, error, count } = await query;

  if (error && /schema cache|column/i.test(error.message || '')) {
    let fallbackQuery = client
      .from('reports')
      .select(basicSelect, { count: 'exact' })
      .order('created_at', { ascending: false })
      .range(filters.offset, filters.offset + filters.limit - 1);

    if (req.user?.id) {
      fallbackQuery = fallbackQuery.eq('user_id', req.user.id);
    }

    fallbackQuery = applyReportFilters(fallbackQuery, filters, {
      includeSourceValue: false,
      includeMetadata: false
    });

    const fallbackResult = await fallbackQuery;
    data = fallbackResult.data;
    error = fallbackResult.error;
    count = fallbackResult.count;
  }

  if (error) {
    return res.status(500).json({ message: error.message });
  }

  const mappedReports = (data || []).map((report) => ({
      id: report.id,
      userId: report.user_id,
      title: report.title,
      summary: report.summary,
      findings: report.findings,
      recommendations: report.recommendations,
      sourceType: report.source_type || 'text',
      sourceValue: report.source_value || null,
      artifactPath: report.artifact_path || null,
      metadata: report.metadata || {},
      createdAt: report.created_at
    }));

  const total = typeof count === 'number' ? count : mappedReports.length;

  return res.json({
    reports: mappedReports,
    pagination: {
      total,
      limit: filters.limit,
      offset: filters.offset,
      returned: mappedReports.length
    },
    filtersApplied: {
      q: filters.q || null,
      sourceType: filters.sourceType,
      risk: filters.risk,
      reportId: filters.reportId,
      iocType: filters.iocType
    }
  });
};

exports.deleteReport = async (req, res) => {
  const client = getSupabaseOrFail(res);

  if (!client) {
    return;
  }

  const reportId = req.params.id;
  if (!reportId) {
    return res.status(400).json({ message: 'Report id is required' });
  }

  let query = client
    .from('reports')
    .delete()
    .eq('id', reportId);

  if (req.user?.id) {
    query = query.eq('user_id', req.user.id);
  }

  const { data, error } = await query.select('id').maybeSingle();

  if (error) {
    return res.status(500).json({ message: error.message });
  }

  if (!data) {
    return res.status(404).json({ message: 'Report not found or already deleted' });
  }

  return res.json({ message: 'Report deleted', id: data.id });
};

exports.exportReportPdf = async (req, res) => {
  const client = getSupabaseOrFail(res);

  if (!client) {
    return;
  }

  const reportId = String(req.params.id || '').trim();
  const mode = String(req.query.mode || 'full').trim().toLowerCase() === 'brief' ? 'brief' : 'full';
  const allowedClassifications = ['confidential', 'internal', 'public'];
  const requestedClassification = String(req.query.classification || '').trim().toLowerCase();
  const envClassification = String(process.env.REPORT_CLASSIFICATION || 'Confidential').trim().toLowerCase();
  const effectiveClassification = allowedClassifications.includes(requestedClassification)
    ? requestedClassification
    : (allowedClassifications.includes(envClassification) ? envClassification : 'confidential');
  const classification = `${effectiveClassification.charAt(0).toUpperCase()}${effectiveClassification.slice(1)}`;
  const watermarkText = String(process.env.REPORT_WATERMARK_TEXT || classification).trim();
  if (!reportId) {
    return res.status(400).json({ message: 'Report id is required' });
  }

  let report;
  try {
    report = await fetchReportById(client, reportId, req.user?.id);
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }

  if (!report) {
    return res.status(404).json({ message: 'Report not found' });
  }

  const mappedReport = {
    id: report.id,
    userId: report.user_id,
    title: report.title,
    summary: report.summary,
    findings: Array.isArray(report.findings) ? report.findings : [],
    recommendations: Array.isArray(report.recommendations) ? report.recommendations : [],
    sourceType: report.source_type || 'text',
    sourceValue: report.source_value || null,
    artifactPath: report.artifact_path || null,
    metadata: report.metadata || {},
    createdAt: report.created_at
  };

  const risk = getRiskProfileFromReport(mappedReport);
  const iocCounts = mappedReport.metadata?.iocIntel?.counts || {};
  const topMitre = (Array.isArray(mappedReport.metadata?.mitreAttack) ? mappedReport.metadata.mitreAttack : [])
    .sort((a, b) => Number(b.score || 0) - Number(a.score || 0))
    .slice(0, 6);
  const generatedBy = req.user?.name || req.user?.email || 'Analyst';
  const organizationName = deriveOrganizationName(req.user);
  const generatedAtLabel = new Date().toLocaleString();

  const filename = `${sanitizeFilename(mappedReport.title)}-${mode === 'brief' ? 'leadership-brief' : 'executive-report'}.pdf`;

  console.log(`[PDF Export] Start: reportId=${reportId}, mode=${mode}, filename=${filename}`);
  console.log(`[PDF Export] Risk level: ${risk.level} (${risk.score}), IOC counts: ${JSON.stringify(iocCounts)}, MITRE count: ${topMitre.length}`);

  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

  try {
    console.log(`[PDF Export] Creating PDFDocument...`);
    const doc = new PDFDocument({ size: 'A4', margin: 50 });
    
    // Add error event handler for the document
    doc.on('error', (error) => {
      console.error('[PDF Export] PDFKit error:', error);
      if (!res.headersSent) {
        res.status(500).json({ message: `PDF generation error: ${error.message}` });
      }
    });

    // Pipe with error handling
    console.log(`[PDF Export] Piping document to response...`);
    doc.pipe(res).on('error', (error) => {
      console.error('[PDF Export] Response stream error:', error);
    });

    console.log(`[PDF Export] Setting up page decoration...`);
    const decoratePage = (showHeader) => {
      drawWatermark(doc, watermarkText);
      if (showHeader) {
        drawBrandedHeader(doc, mappedReport.title, mode);
      }
      drawFooter(doc, {
        organizationName,
        generatedBy,
        classification,
        reportId: mappedReport.id,
        generatedAt: generatedAtLabel
      });
    };

    let autoHeaderForNewPages = true;
    let isProcessingPageAdd = false;
    doc.on('pageAdded', () => {
      if (isProcessingPageAdd) {
        console.log(`[PDF Export] Skipping nested pageAdded event (recursion prevention)`);
        return;
      }
      isProcessingPageAdd = true;
      try {
        console.log(`[PDF Export] Page added, showing header: ${autoHeaderForNewPages}`);
        decoratePage(autoHeaderForNewPages);
      } finally {
        isProcessingPageAdd = false;
      }
    });

    if (mode === 'brief') {
      console.log(`[PDF Export] Rendering brief mode (one-page)...`);
      decoratePage(true);
      writePdfLine(doc, `Report ID: ${mappedReport.id}`);
      console.log(`[PDF Export] Calling renderBriefOnePage...`);
      renderBriefOnePage(doc, mappedReport, risk, iocCounts, topMitre);
      console.log(`[PDF Export] renderBriefOnePage completed`);
    } else {
      console.log(`[PDF Export] Rendering full mode (multi-page)...`);
      autoHeaderForNewPages = false;
      drawWatermark(doc, watermarkText);
      console.log(`[PDF Export] Calling renderFullReportCoverPage...`);
      renderFullReportCoverPage(doc, {
        organizationName,
        title: mappedReport.title,
        riskLabel: `${risk.level}${Number.isFinite(risk.score) ? ` (${risk.score}/100)` : ''}`,
        classification,
        generatedBy,
        createdAtLabel: mappedReport.createdAt ? new Date(mappedReport.createdAt).toLocaleString() : 'Unknown',
        reportId: mappedReport.id
      });
      console.log(`[PDF Export] renderFullReportCoverPage completed`);
      drawFooter(doc, {
        organizationName,
        generatedBy,
        classification,
        reportId: mappedReport.id,
        generatedAt: generatedAtLabel
      });

      autoHeaderForNewPages = true;
      doc.addPage();
      writePdfLine(doc, `Report ID: ${mappedReport.id}`);
      console.log(`[PDF Export] Calling renderFullExecutiveReport...`);
      renderFullExecutiveReport(doc, mappedReport, risk, iocCounts, topMitre);
      console.log(`[PDF Export] renderFullExecutiveReport completed`);
    }

    console.log(`[PDF Export] Ending document...`);
    doc.end();
    console.log(`[PDF Export] Document.end() called`);
  } catch (error) {
    console.error('[PDF Export] Caught error:', error);
    if (!res.headersSent) {
      res.status(500).json({ message: `PDF export error: ${error.message}` });
    }
  }
};

exports.getPdfExportConfig = async (req, res) => {
  const config = getPdfWatermarkConfig();
  return res.json({
    watermark: config,
    allowedClassifications: ['confidential', 'internal', 'public']
  });
};
