const { createSupabaseServiceClient } = require('../config/supabase');
const pdfParse = require('pdf-parse');

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

function mapMitreAttack({ findings = [], iocIntel = { indicators: [] } }) {
  const mapping = new Map();

  const registerTechnique = (id, name, tactic, reason) => {
    if (!mapping.has(id)) {
      mapping.set(id, { id, name, tactic, reasons: [] });
    }
    const entry = mapping.get(id);
    if (reason && !entry.reasons.includes(reason)) {
      entry.reasons.push(reason);
    }
  };

  findings.forEach((finding) => {
    const title = String(finding?.title || '').toLowerCase();

    if (title.includes('weak authentication')) {
      registerTechnique('T1078', 'Valid Accounts', 'Defense Evasion / Persistence', 'Weak authentication patterns detected');
    }

    if (title.includes('injection')) {
      registerTechnique('T1190', 'Exploit Public-Facing Application', 'Initial Access', 'Injection-style patterns were detected');
    }

    if (title.includes('sensitive data exposure')) {
      registerTechnique('T1552', 'Unsecured Credentials', 'Credential Access', 'Sensitive credential-like strings were found');
    }

    if (title.includes('unsafe transport')) {
      registerTechnique('T1071.001', 'Web Protocols', 'Command and Control', 'Potentially unsafe transport references were found');
    }

    if (title.includes('suspicious process')) {
      registerTechnique('T1059', 'Command and Scripting Interpreter', 'Execution', 'Suspicious scripting/process keywords were detected');
    }
  });

  (iocIntel.indicators || []).forEach((indicator) => {
    const tags = Array.isArray(indicator?.tags) ? indicator.tags : [];

    if (tags.includes('credential-lure')) {
      registerTechnique('T1566.002', 'Spearphishing Link', 'Initial Access', 'Credential lure patterns were seen in links');
    }

    if (tags.includes('insecure-transport')) {
      registerTechnique('T1071.001', 'Web Protocols', 'Command and Control', 'IOC used insecure web protocol');
    }

    if (tags.includes('known-malicious')) {
      registerTechnique('T1583', 'Acquire Infrastructure', 'Resource Development', 'Indicator matched external malicious intelligence');
    }
  });

  return [...mapping.values()];
}

function getSupabaseOrFail(res) {
  if (!supabase) {
    res.status(500).json({ message: 'Supabase is not configured. Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY.' });
    return null;
  }

  return supabase;
}

function scoreText(text) {
  const lower = text.toLowerCase();
  const rules = [
    { label: 'Weak authentication patterns', regex: /password|login|credential|otp|mfa/gi, weight: 18 },
    { label: 'Injection risk', regex: /select\s+\*|union\s+select|eval\(|exec\(|command injection|sql/i, weight: 24 },
    { label: 'Sensitive data exposure', regex: /apikey|secret|token|private key|credentials?/gi, weight: 20 },
    { label: 'Unsafe transport or storage', regex: /http:\/\/|plain text|unencrypted|no tls|weak hash/gi, weight: 14 },
    { label: 'Suspicious process or file activity', regex: /powershell|cmd\.exe|rundll32|vbs|macro|autorun/gi, weight: 16 }
  ];

  const findings = rules
    .map((rule) => {
      const matches = lower.match(rule.regex) || [];
      return matches.length
        ? {
            title: rule.label,
            count: matches.length,
            severity: rule.weight >= 20 ? 'high' : rule.weight >= 16 ? 'medium' : 'low'
          }
        : null;
    })
    .filter(Boolean);

  const riskScore = Math.min(100, findings.reduce((sum, finding) => sum + (finding.severity === 'high' ? 24 : finding.severity === 'medium' ? 16 : 10), 0));
  const riskLevel = riskScore >= 65 ? 'High' : riskScore >= 35 ? 'Moderate' : 'Low';
  const threatType = riskLevel === 'High' ? 'Phishing / Scam' : riskLevel === 'Moderate' ? 'Suspicious' : 'Safe';
  const explanation =
    riskLevel === 'High'
      ? 'Multiple strong malicious indicators were detected in the submitted content.'
      : riskLevel === 'Moderate'
        ? 'Some suspicious indicators were found and should be reviewed before trusting the content.'
        : 'No strong malicious indicators were detected in the submitted content.';

  return {
    findings,
    riskScore,
    riskLevel,
    threatType,
    explanation,
    recommendations: [
      'Review exposed secrets and rotate any credential found in the sample.',
      'Harden authentication, storage, and transport defaults.',
      'Validate all inputs before execution or persistence.'
    ]
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
    { label: 'IP address in host', regex: /(?:\d{1,3}\.){3}\d{1,3}/, weight: 22 },
    { label: 'Shortened URL service', regex: /bit\.ly|tinyurl|t\.co|ow\.ly|is\.gd|cutt\.ly/, weight: 22 },
    { label: 'Credential harvesting keywords', regex: /login|verify|secure|update|account|signin|password/, weight: 20 },
    { label: 'Suspicious TLD', regex: /\.(ru|tk|top|xyz|click|zip|mov)$/, weight: 18 },
    { label: 'Long or complex path', regex: /\/.{60,}/, weight: 12 }
  ];

  const findings = rules
    .map((rule) => {
      const matched = rule.regex.test(urlText);
      rule.regex.lastIndex = 0;
      return matched
        ? {
            title: rule.label,
            count: 1,
            severity: rule.weight >= 20 ? 'high' : rule.weight >= 16 ? 'medium' : 'low'
          }
        : null;
    })
    .filter(Boolean);

  const riskScore = Math.min(100, findings.reduce((sum, finding) => sum + (finding.severity === 'high' ? 24 : finding.severity === 'medium' ? 16 : 8), 0));
  const riskLevel = riskScore >= 65 ? 'High' : riskScore >= 35 ? 'Moderate' : 'Low';

  return {
    findings,
    riskScore,
    riskLevel,
    recommendations: [
      'Check the domain carefully before opening the link.',
      'Avoid entering credentials if the site is unexpected or newly registered.',
      'Use a safe browser or detonation environment for suspicious URLs.'
    ]
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
  const basicSelect = 'id, user_id, title, summary, findings, recommendations, created_at';

  let { data, error } = await client
    .from('reports')
    .insert(fullInsertPayload)
    .select(fullSelect)
    .single();

  if (error && /schema cache|column/i.test(error.message || '')) {
    const fallbackInsertPayload = {
      user_id: payload.userId,
      title: payload.title,
      summary: payload.summary,
      findings: payload.findings,
      recommendations: payload.recommendations
    };

    const fallbackResult = await client
      .from('reports')
      .insert(fallbackInsertPayload)
      .select(basicSelect)
      .single();

    data = fallbackResult.data;
    error = fallbackResult.error;
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
  const mitreAttack = mapMitreAttack({ findings: analysis.findings, iocIntel });

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
  const mitreAttack = mapMitreAttack({ findings: analysis.findings, iocIntel });

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
  const mitreAttack = mapMitreAttack({ findings: analysis.findings, iocIntel });
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
