const { createSupabaseServiceClient } = require('../config/supabase');
const pdfParse = require('pdf-parse');

const supabase = createSupabaseServiceClient();
const storageBucket = process.env.SUPABASE_STORAGE_BUCKET || 'analysis-artifacts';

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
      metadata: { inputLength: text.length }
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
    analysis
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
      metadata: { hostname: (() => {
        try {
          return new URL(String(url).trim()).hostname;
        } catch (error) {
          return null;
        }
      })() }
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
    analysis
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

  const analysis = scoreText(extractedText || req.file.originalname || '');
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
        extractedLength: extractedText.length
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
    analysis
  });
};

exports.listReports = async (req, res) => {
  const client = getSupabaseOrFail(res);

  if (!client) {
    return;
  }

  const fullSelect = 'id, user_id, title, summary, findings, recommendations, source_type, source_value, artifact_path, metadata, created_at';
  const basicSelect = 'id, user_id, title, summary, findings, recommendations, created_at';

  let query = client
    .from('reports')
    .select(fullSelect)
    .order('created_at', { ascending: false });

  if (req.user?.id) {
    query = query.eq('user_id', req.user.id);
  }

  let { data, error } = await query;

  if (error && /schema cache|column/i.test(error.message || '')) {
    let fallbackQuery = client
      .from('reports')
      .select(basicSelect)
      .order('created_at', { ascending: false });

    if (req.user?.id) {
      fallbackQuery = fallbackQuery.eq('user_id', req.user.id);
    }

    const fallbackResult = await fallbackQuery;
    data = fallbackResult.data;
    error = fallbackResult.error;
  }

  if (error) {
    return res.status(500).json({ message: error.message });
  }

  return res.json({
    reports: data.map((report) => ({
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
    }))
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
