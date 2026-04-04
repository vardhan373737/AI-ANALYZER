const API_BASE = '/api';

function getToken() {
  return localStorage.getItem('aca_token');
}

function getUser() {
  const raw = localStorage.getItem('aca_user');
  return raw ? JSON.parse(raw) : null;
}

function setSession({ token, user }) {
  if (token) {
    localStorage.setItem('aca_token', token);
  }
  if (user) {
    localStorage.setItem('aca_user', JSON.stringify(user));
  }
}

function clearSession() {
  localStorage.removeItem('aca_token');
  localStorage.removeItem('aca_user');
}

function showToast(message) {
  let toast = document.querySelector('.toast');
  if (!toast) {
    toast = document.createElement('div');
    toast.className = 'toast';
    document.body.appendChild(toast);
  }
  toast.textContent = message;
  toast.classList.add('show');
  window.clearTimeout(showToast._timer);
  showToast._timer = window.setTimeout(() => toast.classList.remove('show'), 2800);
}

function debounce(callback, waitMs) {
  let timer = null;
  return (...args) => {
    window.clearTimeout(timer);
    timer = window.setTimeout(() => callback(...args), waitMs);
  };
}

function showConfirmModal({
  title = 'Confirm action',
  message = 'Are you sure?',
  confirmText = 'Confirm',
  cancelText = 'Cancel'
} = {}) {
  return new Promise((resolve) => {
    const existing = document.querySelector('.confirm-modal-backdrop');
    if (existing) {
      existing.remove();
    }

    const backdrop = document.createElement('div');
    backdrop.className = 'confirm-modal-backdrop';
    backdrop.innerHTML = `
      <div class="confirm-modal" role="dialog" aria-modal="true" aria-labelledby="confirm-modal-title">
        <h3 id="confirm-modal-title">${title}</h3>
        <p>${message}</p>
        <div class="confirm-modal-actions">
          <button type="button" class="inline-link" data-confirm-cancel>${cancelText}</button>
          <button type="button" class="btn btn-primary" data-confirm-ok>${confirmText}</button>
        </div>
      </div>
    `;

    const cleanup = (result) => {
      window.removeEventListener('keydown', handleKeydown);
      backdrop.remove();
      resolve(result);
    };

    const handleKeydown = (event) => {
      if (event.key === 'Escape') {
        cleanup(false);
      }
    };

    backdrop.addEventListener('click', (event) => {
      if (event.target === backdrop) {
        cleanup(false);
      }
    });

    backdrop.querySelector('[data-confirm-cancel]').addEventListener('click', () => cleanup(false));
    backdrop.querySelector('[data-confirm-ok]').addEventListener('click', () => cleanup(true));

    document.body.appendChild(backdrop);
    window.addEventListener('keydown', handleKeydown);
  });
}

async function requestJSON(url, options = {}) {
  const isFormData = typeof FormData !== 'undefined' && options.body instanceof FormData;
  const response = await fetch(url, {
    headers: {
      ...(!isFormData ? { 'Content-Type': 'application/json' } : {}),
      ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}),
      ...(options.headers || {})
    },
    ...options
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.message || 'Request failed');
  }
  return data;
}

function buildReportsQueryParams(params = {}) {
  const query = new URLSearchParams();

  if (params.q) query.set('q', String(params.q));
  if (params.sourceType && params.sourceType !== 'all') query.set('sourceType', String(params.sourceType));
  if (params.risk && params.risk !== 'all') query.set('risk', String(params.risk));
  if (params.reportId) query.set('reportId', String(params.reportId));
  if (params.iocType && params.iocType !== 'all') query.set('iocType', String(params.iocType));
  if (params.limit) query.set('limit', String(params.limit));
  if (params.offset !== undefined && params.offset !== null) query.set('offset', String(params.offset));

  const value = query.toString();
  return value ? `?${value}` : '';
}

function getPostAuthRedirectTarget() {
  const params = new URLSearchParams(window.location.search);
  const requestedTarget = String(params.get('next') || '').trim();
  const safeTargetPattern = /^[a-z0-9_-]+\.html(?:\?[a-z0-9_=&%-]*)?$/i;

  if (requestedTarget && safeTargetPattern.test(requestedTarget)) {
    return requestedTarget;
  }

  return 'dashboard.html';
}

function getPostAuthHint(target) {
  const normalizedTarget = String(target || '').trim();
  const friendlyNames = {
    'report.html': 'reports',
    'mitre.html': 'the MITRE matrix',
    'dashboard.html': 'the dashboard',
    'analyzer.html': 'the analyzer'
  };

  const [pageName] = normalizedTarget.split('?');
  const friendlyName = friendlyNames[pageName] || pageName.replace(/\.html$/i, '') || 'the requested page';
  return `You will return to ${friendlyName} after sign-in.`;
}

function wireAuthForms() {
  const loginForm = document.querySelector('[data-login-form]');
  const registerForm = document.querySelector('[data-register-form]');
  const postAuthRedirect = getPostAuthRedirectTarget();
  const postAuthHintNode = document.querySelector('[data-login-next-hint]');
  const resetBannerNode = document.querySelector('[data-login-reset-banner]');

  if (postAuthHintNode) {
    const params = new URLSearchParams(window.location.search);
    if (params.get('next')) {
      postAuthHintNode.textContent = getPostAuthHint(postAuthRedirect);
      postAuthHintNode.hidden = false;
    }
  }

  if (resetBannerNode) {
    const params = new URLSearchParams(window.location.search);
    if (params.get('reset') === '1') {
      resetBannerNode.textContent = 'Password reset complete. Please sign in with your new password.';
      resetBannerNode.hidden = false;
    }
  }

  if (loginForm) {
    const forgotPasswordButton = loginForm.querySelector('[data-forgot-password]');
    const emailInput = loginForm.querySelector('input[name="email"]');

    if (forgotPasswordButton) {
      forgotPasswordButton.addEventListener('click', async () => {
        const emailValue = String(emailInput?.value || '').trim();
        if (!emailValue) {
          showToast('Enter your email first to reset password');
          return;
        }

        try {
          const data = await requestJSON(`${API_BASE}/auth/forgot-password`, {
            method: 'POST',
            body: JSON.stringify({ email: emailValue })
          });
          showToast(data.message || 'Password reset link sent');
        } catch (error) {
          showToast(error.message);
        }
      });
    }

    loginForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      const formData = new FormData(loginForm);
      const payload = Object.fromEntries(formData.entries());
      try {
        const data = await requestJSON(`${API_BASE}/auth/login`, {
          method: 'POST',
          body: JSON.stringify(payload)
        });
        setSession(data);
        showToast('Login successful');
        window.location.href = postAuthRedirect;
      } catch (error) {
        showToast(error.message);
      }
    });
  }

  if (registerForm) {
    registerForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      const formData = new FormData(registerForm);
      const payload = Object.fromEntries(formData.entries());
      try {
        const data = await requestJSON(`${API_BASE}/auth/register`, {
          method: 'POST',
          body: JSON.stringify(payload)
        });
        setSession(data);
        showToast('Account created');
        window.location.href = postAuthRedirect;
      } catch (error) {
        showToast(error.message);
      }
    });
  }
}

function wireNav() {
  const logoutButtons = document.querySelectorAll('[data-logout]');
  logoutButtons.forEach((button) => {
    button.addEventListener('click', () => {
      clearSession();
      window.location.href = '/';
    });
  });
}

function getRiskProfile(reportOrSummary) {
  if (typeof reportOrSummary === 'object' && reportOrSummary) {
    const report = reportOrSummary;
    const metadataRisk = report.metadata?.riskEngine;
    const inlineRisk = report.riskEngine;
    const structuredRisk = metadataRisk || inlineRisk;

    if (structuredRisk && structuredRisk.level) {
      const numericScore = Number(structuredRisk.score);
      return {
        level: String(structuredRisk.level).toLowerCase(),
        scoreText: Number.isFinite(numericScore) ? `${Math.round(numericScore)}/100` : null,
        explanation: structuredRisk.explanation || null,
        topDrivers: Array.isArray(structuredRisk.topDrivers) ? structuredRisk.topDrivers : []
      };
    }
  }

  const summary = typeof reportOrSummary === 'string'
    ? reportOrSummary
    : String(reportOrSummary?.summary || '');

  const levelMatch = summary.match(/Risk\s*level:\s*(High|Moderate|Low)/i);
  const scoreMatch = summary.match(/\((\d+\/100)\)/i);

  return {
    level: levelMatch ? levelMatch[1].toLowerCase() : 'low',
    scoreText: scoreMatch ? scoreMatch[1] : null,
    explanation: null,
    topDrivers: []
  };
}

function getRiskDisplay(reportOrSummary) {
  const profile = getRiskProfile(reportOrSummary);
  const level = profile.level;
  const score = profile.scoreText ? ` (${profile.scoreText})` : '';

  if (level === 'high') {
    return {
      badgeClass: 'danger',
      badgeText: `Danger${score}`,
      statusText: profile.explanation || 'High risk detected. Treat this as potentially malicious.'
    };
  }

  if (level === 'moderate') {
    return {
      badgeClass: 'warn',
      badgeText: `Needs Review${score}`,
      statusText: profile.explanation || 'Moderate risk. Review carefully before trusting it.'
    };
  }

  return {
    badgeClass: 'success',
    badgeText: `Safe${score}`,
    statusText: profile.explanation || 'Looks good. No strong malicious indicators were found.'
  };
}

function setSubmitBusy(form, isBusy, busyText = 'Processing...') {
  if (!form) {
    return;
  }

  const submitButton = form.querySelector('button[type="submit"]');
  if (!submitButton) {
    return;
  }

  if (isBusy) {
    submitButton.dataset.originalText = submitButton.textContent;
    submitButton.textContent = busyText;
    submitButton.disabled = true;
    return;
  }

  submitButton.textContent = submitButton.dataset.originalText || submitButton.textContent;
  submitButton.disabled = false;
}

async function downloadExecutiveReportPdf(reportId, mode = 'full', classification = 'confidential') {
  const token = getToken();
  if (!token) {
    throw new Error('Session expired. Please login again.');
  }

  const normalizedMode = String(mode || 'full').toLowerCase() === 'brief' ? 'brief' : 'full';
  const normalizedClassification = ['confidential', 'internal', 'public'].includes(String(classification || '').toLowerCase())
    ? String(classification).toLowerCase()
    : 'confidential';
  const query = new URLSearchParams({
    mode: normalizedMode,
    classification: normalizedClassification
  });
  const exportUrl = `${API_BASE}/analyze/reports/${encodeURIComponent(reportId)}/pdf?${query.toString()}`;

  const response = await fetch(exportUrl, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${token}`
    }
  });

  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    throw new Error(data.message || 'Failed to generate executive PDF');
  }

  const blob = await response.blob();
  const contentDisposition = response.headers.get('Content-Disposition') || '';
  const filenameMatch = contentDisposition.match(/filename="?([^";]+)"?/i);
  const filename = filenameMatch ? filenameMatch[1] : `executive-report-${reportId}.pdf`;

  const blobUrl = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = blobUrl;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(blobUrl);
}

function getClassificationImpact(classification, watermarkConfig = null) {
  const normalized = ['confidential', 'internal', 'public'].includes(String(classification || '').toLowerCase())
    ? String(classification).toLowerCase()
    : 'confidential';

  const labelByClassification = {
    confidential: 'CONFIDENTIAL',
    internal: 'INTERNAL',
    public: 'PUBLIC'
  };

  const watermarkSource = String(watermarkConfig?.source || 'classification').toLowerCase();
  const configuredText = String(watermarkConfig?.text || '').trim();

  let watermarkMessage;
  if (watermarkSource === 'override') {
    watermarkMessage = `Watermark uses REPORT_WATERMARK_TEXT override: "${configuredText || 'custom value'}".`;
  } else if (watermarkSource === 'disabled') {
    watermarkMessage = 'Watermark is disabled by server setting (REPORT_WATERMARK_TEXT=none).';
  } else {
    watermarkMessage = `${labelByClassification[normalized]} watermark is applied from selected classification.`;
  }

  if (normalized === 'public') {
    return {
      heading: 'Public export',
      watermark: watermarkMessage,
      footer: 'Footer shows classification as Public with organization and generated-by details.'
    };
  }

  if (normalized === 'internal') {
    return {
      heading: 'Internal export',
      watermark: watermarkMessage,
      footer: 'Footer shows classification as Internal with organization and generated-by details.'
    };
  }

  return {
    heading: 'Confidential export',
    watermark: watermarkMessage,
    footer: 'Footer shows classification as Confidential with organization and generated-by details.'
  };
}

function getWatermarkModeLabel(source) {
  const normalizedSource = String(source || '').toLowerCase();
  if (normalizedSource === 'override') return 'Override';
  if (normalizedSource === 'disabled') return 'Disabled';
  return 'Classification';
}

function getWatermarkBadgeToneClass(source, classification) {
  const normalizedSource = String(source || '').toLowerCase();
  const normalizedClassification = String(classification || 'confidential').toLowerCase();

  if (normalizedSource === 'override') {
    return 'is-override';
  }

  if (normalizedSource === 'disabled') {
    return 'is-disabled';
  }

  if (normalizedClassification === 'public') {
    return 'is-public';
  }

  if (normalizedClassification === 'internal') {
    return 'is-internal';
  }

  return 'is-confidential';
}

function getCachedPdfConfig() {
  const raw = localStorage.getItem('aca_pdf_config_cache');
  if (!raw) {
    return null;
  }

  try {
    const parsed = JSON.parse(raw);
    const expiresAt = Number(parsed?.expiresAt || 0);
    if (!expiresAt || Date.now() > expiresAt) {
      localStorage.removeItem('aca_pdf_config_cache');
      return null;
    }

    return {
      value: parsed.value || null,
      checkedAt: Number(parsed?.checkedAt || 0) || 0
    };
  } catch (error) {
    localStorage.removeItem('aca_pdf_config_cache');
    return null;
  }
}

function setCachedPdfConfig(value, ttlMs = 10 * 60 * 1000) {
  const now = Date.now();
  try {
    localStorage.setItem(
      'aca_pdf_config_cache',
      JSON.stringify({
        value,
        checkedAt: now,
        expiresAt: now + ttlMs
      })
    );
  } catch (error) {
    // Ignore cache write failures (private mode / quota issues).
  }
}

function formatElapsedTimeShort(timestamp) {
  const value = Number(timestamp || 0);
  if (!value || !Number.isFinite(value)) {
    return 'never';
  }

  const deltaMs = Math.max(0, Date.now() - value);
  const seconds = Math.floor(deltaMs / 1000);
  if (seconds < 60) {
    return `${seconds}s ago`;
  }

  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) {
    return `${minutes}m ago`;
  }

  const hours = Math.floor(minutes / 60);
  return `${hours}h ago`;
}

function getPdfGenerationHistory(reportId) {
  const key = `aca_pdf_generated_${String(reportId || '').trim()}`;
  if (!reportId) {
    return { full: 0, brief: 0 };
  }

  const raw = localStorage.getItem(key);
  if (!raw) {
    return { full: 0, brief: 0 };
  }

  try {
    const parsed = JSON.parse(raw);
    return {
      full: Number(parsed?.full || 0) || 0,
      brief: Number(parsed?.brief || 0) || 0
    };
  } catch (error) {
    localStorage.removeItem(key);
    return { full: 0, brief: 0 };
  }
}

function setPdfGenerationHistory(reportId, history) {
  const key = `aca_pdf_generated_${String(reportId || '').trim()}`;
  if (!reportId) {
    return;
  }

  try {
    localStorage.setItem(
      key,
      JSON.stringify({
        full: Number(history?.full || 0) || 0,
        brief: Number(history?.brief || 0) || 0
      })
    );
  } catch (error) {
    // Ignore storage write failures.
  }
}

function renderPendingReportMessage(output, sourceLabel) {
  if (!output) {
    return;
  }

  output.innerHTML = `
    <div class="result-grid">
      <div><strong>Status:</strong> Please wait...</div>
      <div><strong>Processing:</strong> ${sourceLabel} analysis is running on the server.</div>
      <div><strong>Report:</strong> Your report will appear in Reports once saved.</div>
    </div>
  `;
}

function renderSavedReportMessage(output, data) {
  if (!output) {
    return;
  }

  const analysis = data.analysis || {};
  const report = data.report || {};
  const iocIntel = analysis.iocIntel || {};
  const iocCounts = iocIntel.counts || {};
  const riskProfile = getRiskProfile({
    riskEngine: analysis.riskEngine,
    summary: report.summary || analysis.summary || ''
  });
  const mitreAttack = analysis.mitreAttack || report.metadata?.mitreAttack || [];
  const topDrivers = riskProfile.topDrivers.length ? riskProfile.topDrivers.join(', ') : 'No primary drivers';
  output.innerHTML = `
    <div class="result-grid">
      <div><strong>Threat Type:</strong> ${analysis.threatType || (analysis.riskLevel === 'High' ? 'Phishing / Scam' : analysis.riskLevel === 'Moderate' ? 'Suspicious' : 'Safe')}</div>
      <div><strong>Risk Level:</strong> ${riskProfile.level ? `${riskProfile.level.charAt(0).toUpperCase()}${riskProfile.level.slice(1)}` : (analysis.riskLevel || 'Unknown')}${riskProfile.scoreText ? ` (${riskProfile.scoreText})` : analysis.riskScore !== undefined ? ` (${analysis.riskScore}/100)` : ''}</div>
      <div><strong>Explanation:</strong> ${analysis.explanation || 'Analysis completed on server.'}</div>
      <div><strong>Top risk drivers:</strong> ${topDrivers}</div>
      <div><strong>Indicators:</strong> ${(analysis.findings || []).map((item) => item.title).join(', ') || 'None found'}</div>
      <div><strong>IOC summary:</strong> ${iocCounts.total || 0} total (${iocCounts.urls || 0} URLs, ${iocCounts.ips || 0} IPs, ${iocCounts.domains || 0} domains, ${iocCounts.hashes || 0} hashes)</div>
      <div><strong>High-confidence IOCs:</strong> ${iocIntel.highConfidenceCount || 0}</div>
      <div><strong>MITRE mapping:</strong> ${mitreAttack.length ? mitreAttack.map((item) => `${item.id} ${item.name}`).join(', ') : 'No mapped techniques'}</div>
      <div><strong>Recommendations:</strong> ${(analysis.recommendations || []).join(' ') || 'No recommendations available.'}</div>
      <div><strong>Report:</strong> Saved on server. View it in <a class="inline-link" href="report.html">Reports</a>.</div>
      ${report.id ? `<div><a class="inline-link" href="report.html?id=${report.id}">Open this report</a></div>` : ''}
    </div>
  `;
}

function getReportRiskLevel(report) {
  const riskLevel = String(report?.metadata?.riskEngine?.level || '').toLowerCase();
  if (riskLevel === 'high' || riskLevel === 'moderate' || riskLevel === 'low') {
    return riskLevel;
  }

  const fallback = getRiskProfile(report?.summary || '').level;
  return ['high', 'moderate', 'low'].includes(fallback) ? fallback : 'low';
}

function filterReports(reports, filters) {
  const query = String(filters?.query || '').trim().toLowerCase();
  const iocType = String(filters?.iocType || 'all');
  const risk = String(filters?.risk || 'all');

  return (reports || []).filter((report) => {
    const metadata = report.metadata || {};
    const iocCounts = metadata.iocIntel?.counts || {};
    const mitreAttack = Array.isArray(metadata.mitreAttack) ? metadata.mitreAttack : [];

    if (iocType !== 'all' && Number(iocCounts[iocType] || 0) <= 0) {
      return false;
    }

    if (risk !== 'all' && getReportRiskLevel(report) !== risk) {
      return false;
    }

    if (!query) {
      return true;
    }

    const haystack = [
      report.title,
      report.summary,
      report.sourceType,
      report.sourceValue,
      ...mitreAttack.map((item) => `${item.id} ${item.name}`)
    ]
      .filter(Boolean)
      .join(' ')
      .toLowerCase();

    return haystack.includes(query);
  });
}

function aggregateIocMetrics(reports) {
  const totals = {
    total: 0,
    highConfidence: 0,
    urls: 0,
    ips: 0,
    domains: 0,
    hashes: 0
  };

  const occurrenceMap = new Map();
  const providerMalicious = {
    virustotal: 0,
    abuseipdb: 0,
    total: 0
  };

  (reports || []).forEach((report) => {
    const metadata = report.metadata || {};
    const intel = metadata.iocIntel || {};
    const counts = intel.counts || {};
    const indicators = Array.isArray(intel.indicators) ? intel.indicators : [];

    totals.total += Number(counts.total || 0);
    totals.highConfidence += Number(intel.highConfidenceCount || 0);
    totals.urls += Number(counts.urls || 0);
    totals.ips += Number(counts.ips || 0);
    totals.domains += Number(counts.domains || 0);
    totals.hashes += Number(counts.hashes || 0);

    indicators.forEach((indicator) => {
      if (!indicator || !indicator.type || !indicator.value) {
        return;
      }

      const key = `${indicator.type}:${indicator.value}`;
      if (!occurrenceMap.has(key)) {
        occurrenceMap.set(key, {
          type: indicator.type,
          value: indicator.value,
          count: 0,
          maxConfidence: 0
        });
      }

      const current = occurrenceMap.get(key);
      current.count += 1;
      current.maxConfidence = Math.max(current.maxConfidence, Number(indicator.confidence || 0));

      const externalIntel = Array.isArray(indicator.externalIntel) ? indicator.externalIntel : [];
      externalIntel.forEach((intelItem) => {
        if (intelItem.classification !== 'malicious') {
          return;
        }

        if (intelItem.provider === 'virustotal') {
          providerMalicious.virustotal += 1;
        }

        if (intelItem.provider === 'abuseipdb') {
          providerMalicious.abuseipdb += 1;
        }

        providerMalicious.total += 1;
      });
    });
  });

  const categoryEntries = [
    ['URLs', totals.urls],
    ['IPs', totals.ips],
    ['Domains', totals.domains],
    ['Hashes', totals.hashes]
  ];

  categoryEntries.sort((a, b) => b[1] - a[1]);
  const topCategory = categoryEntries[0] && categoryEntries[0][1] > 0
    ? `${categoryEntries[0][0]} (${categoryEntries[0][1]})`
    : 'None';

  const topIndicators = [...occurrenceMap.values()]
    .sort((a, b) => (b.count - a.count) || (b.maxConfidence - a.maxConfidence))
    .slice(0, 5);

  return {
    totals,
    topCategory,
    topIndicators,
    providerMalicious
  };
}

function renderDashboard() {
  const nameNode = document.querySelector('[data-user-name]');
  const roleNode = document.querySelector('[data-user-role]');
  const tokenNode = document.querySelector('[data-token-state]');
  const sourceStatusRoot = document.querySelector('[data-source-status]');
  const sourceLocalNode = document.querySelector('[data-source-local]');
  const sourceVtNode = document.querySelector('[data-source-vt]');
  const sourceAbuseIpdbNode = document.querySelector('[data-source-abuseipdb]');
  const reportList = document.querySelector('[data-report-list]');
  const iocTotalNode = document.querySelector('[data-ioc-total]');
  const iocHighConfidenceNode = document.querySelector('[data-ioc-high-confidence]');
  const iocTopCategoryNode = document.querySelector('[data-ioc-top-category]');
  const iocTopList = document.querySelector('[data-ioc-top-list]');
  const vtMaliciousNode = document.querySelector('[data-vt-malicious-hits]');
  const abuseIpdbMaliciousNode = document.querySelector('[data-abuseipdb-malicious-hits]');
  const externalMaliciousTotalNode = document.querySelector('[data-external-malicious-total]');

  const isDashboardContext = Boolean(nameNode || roleNode || tokenNode || reportList);
  if (!isDashboardContext) {
    return;
  }

  const user = getUser();
  if (!user) {
    window.location.href = 'login.html';
    return;
  }

  if (nameNode) nameNode.textContent = user.name || 'Analyst';
  if (roleNode) roleNode.textContent = user.role || 'analyst';
  if (tokenNode) tokenNode.textContent = getToken() ? 'Session active' : 'No session';

  const applySourceChipState = (node, prefix, state) => {
    if (!node) {
      return;
    }

    const normalizedState = String(state || '').toLowerCase();
    const enabled = normalizedState === 'enabled' || normalizedState === 'active';
    const label = enabled ? (normalizedState === 'active' ? 'Active' : 'Enabled') : 'Disabled';

    node.classList.remove('is-active', 'is-enabled', 'is-disabled');
    node.classList.add(enabled ? (normalizedState === 'active' ? 'is-active' : 'is-enabled') : 'is-disabled');
    node.textContent = `${prefix}: ${label}`;
  };

  if (sourceStatusRoot) {
    applySourceChipState(sourceLocalNode, 'Local rules', 'active');
    applySourceChipState(sourceVtNode, 'VirusTotal', 'disabled');
    applySourceChipState(sourceAbuseIpdbNode, 'AbuseIPDB', 'disabled');
  }

  if (reportList) {
    requestJSON(`${API_BASE}/analyze/reports${buildReportsQueryParams({ limit: 100, offset: 0 })}`)
      .then((data) => {
        const iocMetrics = aggregateIocMetrics(data.reports || []);

        const externalAvailability = (data.reports || []).reduce(
          (acc, report) => {
            const summary = report?.metadata?.iocIntel?.externalSummary || {};
            if (summary.virusTotalEnabled === true) {
              acc.virusTotalEnabled = true;
            }
            if (summary.abuseIpdbEnabled === true) {
              acc.abuseIpdbEnabled = true;
            }
            return acc;
          },
          {
            virusTotalEnabled: false,
            abuseIpdbEnabled: false
          }
        );

        if (sourceStatusRoot) {
          applySourceChipState(sourceLocalNode, 'Local rules', 'active');
          applySourceChipState(sourceVtNode, 'VirusTotal', externalAvailability.virusTotalEnabled ? 'enabled' : 'disabled');
          applySourceChipState(sourceAbuseIpdbNode, 'AbuseIPDB', externalAvailability.abuseIpdbEnabled ? 'enabled' : 'disabled');
        }

        if (iocTotalNode) iocTotalNode.textContent = String(iocMetrics.totals.total);
        if (iocHighConfidenceNode) iocHighConfidenceNode.textContent = String(iocMetrics.totals.highConfidence);
        if (iocTopCategoryNode) iocTopCategoryNode.textContent = iocMetrics.topCategory;
        if (vtMaliciousNode) vtMaliciousNode.textContent = String(iocMetrics.providerMalicious.virustotal);
        if (abuseIpdbMaliciousNode) abuseIpdbMaliciousNode.textContent = String(iocMetrics.providerMalicious.abuseipdb);
        if (externalMaliciousTotalNode) externalMaliciousTotalNode.textContent = String(iocMetrics.providerMalicious.total);
        if (iocTopList) {
          iocTopList.innerHTML = iocMetrics.topIndicators.length
            ? iocMetrics.topIndicators
                .map((item) => `
                  <div class="list-item">
                    <div class="section-head" style="margin-bottom:8px;">
                      <strong>${item.type.toUpperCase()}</strong>
                      <span class="badge ${item.maxConfidence >= 0.75 ? 'danger' : item.maxConfidence >= 0.5 ? 'warn' : 'success'}">${Math.round(item.maxConfidence * 100)}% confidence</span>
                    </div>
                    <p class="muted">${item.value}</p>
                    <p class="muted">Seen in ${item.count} report${item.count > 1 ? 's' : ''}</p>
                  </div>
                `)
                .join('')
            : '<div class="list-item">No IOC data yet. Run an analysis to populate this section.</div>';
        }

        reportList.innerHTML = data.reports.length
          ? data.reports
              .map((report) => {
                const risk = getRiskDisplay(report);
                return `
                  <div class="list-item">
                    <div class="section-head" style="margin-bottom:8px;">
                      <strong>${report.title}</strong>
                      <span class="badge ${risk.badgeClass}">${risk.badgeText}</span>
                    </div>
                    <p class="muted">${report.sourceType || 'text'}${report.sourceValue ? ` · ${report.sourceValue}` : ''}</p>
                    <p class="muted">Created: ${report.createdAt ? new Date(report.createdAt).toLocaleString() : 'Unknown'}</p>
                    <p class="muted">${risk.statusText}</p>
                    <p>${report.recommendations[0] || 'No recommendations available.'}</p>
                    <a class="inline-link" href="report.html?id=${report.id}">Open report</a>
                    <button class="inline-link inline-link-danger" type="button" data-delete-report-id="${report.id}">Delete</button>
                  </div>
                `;
              })
              .join('')
          : '<div class="list-item">No reports yet. Run your first analysis.</div>';

        reportList.querySelectorAll('[data-delete-report-id]').forEach((button) => {
          button.addEventListener('click', async () => {
            const reportId = button.getAttribute('data-delete-report-id');
            if (!reportId) {
              return;
            }

            const shouldDelete = await showConfirmModal({
              title: 'Delete report',
              message: 'This report will be permanently removed.',
              confirmText: 'Delete'
            });

            if (!shouldDelete) {
              return;
            }

            try {
              await requestJSON(`${API_BASE}/analyze/reports/${reportId}`, { method: 'DELETE' });
              button.closest('.list-item')?.remove();
              if (!reportList.querySelector('.list-item')) {
                reportList.innerHTML = '<div class="list-item">No reports yet. Run your first analysis.</div>';
              }
              showToast('Report deleted');
            } catch (error) {
              showToast(error.message);
            }
          });
        });
      })
      .catch((error) => {
        reportList.innerHTML = `<div class="list-item">${error.message}</div>`;
        if (sourceStatusRoot) {
          applySourceChipState(sourceLocalNode, 'Local rules', 'active');
          applySourceChipState(sourceVtNode, 'VirusTotal', 'disabled');
          applySourceChipState(sourceAbuseIpdbNode, 'AbuseIPDB', 'disabled');
        }
        if (iocTopList) {
          iocTopList.innerHTML = `<div class="list-item">${error.message}</div>`;
        }
      });
  }
}

function scoreRisk(text) {
  const value = text.toLowerCase();
  const matches = [
    /https?:\/\/[^\s]+/g,
    /password|credential|secret|token|login/gi,
    /wire transfer|urgent|verify immediately|account suspended/gi,
    /attach|attachment|invoice|docx?|pdf/gi
  ].reduce((count, pattern) => count + ((value.match(pattern) || []).length), 0);

  if (matches >= 7) return { level: 'High', score: 82 };
  if (matches >= 3) return { level: 'Medium', score: 52 };
  return { level: 'Low', score: 18 };
}

function wireAnalyzer() {
  const form = document.querySelector('[data-analyzer-form]');
  const output = document.querySelector('[data-analyzer-output]');
  const urlForm = document.querySelector('[data-url-scan-form]');
  const uploadForm = document.querySelector('[data-upload-form]');
  const fileInput = document.querySelector('[data-file-input]');
  const fileMeta = document.querySelector('[data-file-meta]');
  const sampleButtons = document.querySelectorAll('[data-sample-text]');

  if (sampleButtons.length) {
    sampleButtons.forEach((button) => {
      button.addEventListener('click', () => {
        const target = document.querySelector('[data-analysis-input]');
        if (target) target.value = button.dataset.sampleText || '';
      });
    });
  }

  if (fileInput && fileMeta) {
    fileInput.addEventListener('change', () => {
      const file = fileInput.files && fileInput.files[0];
      fileMeta.textContent = file ? `${file.name} · ${Math.round(file.size / 1024)} KB` : 'No file selected';
    });
  }

  if (form) {
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      const formData = new FormData(form);
      const text = String(formData.get('text') || '');
      const title = String(formData.get('title') || 'Manual analysis');
      renderPendingReportMessage(output, 'Text input');
      setSubmitBusy(form, true, 'Analyzing...');
      try {
        const serverResult = await requestJSON(`${API_BASE}/analyze`, {
          method: 'POST',
          body: JSON.stringify({ title, text })
        });
        renderSavedReportMessage(output, serverResult);
        showToast('Analysis complete. Report saved.');
      } catch (error) {
        output.innerHTML = `<div class="result-grid"><div><strong>Threat Type:</strong> Unable to analyze</div><div><strong>Risk Level:</strong> Unknown</div><div><strong>Explanation:</strong> Server analysis failed. Please try again.</div><div><strong>Indicators:</strong> None</div></div>`;
        showToast(error.message);
      } finally {
        setSubmitBusy(form, false);
      }
    });
  }

  if (urlForm) {
    urlForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      const formData = new FormData(urlForm);
      const title = String(formData.get('title') || 'URL scan');
      const url = String(formData.get('url') || '').trim();

      if (!url) {
        showToast('Enter a URL to scan');
        return;
      }

      renderPendingReportMessage(output, 'URL');
      setSubmitBusy(urlForm, true, 'Scanning...');

      try {
        const result = await requestJSON(`${API_BASE}/analyze/url`, {
          method: 'POST',
          body: JSON.stringify({ title, url })
        });
        renderSavedReportMessage(output, result);
        showToast('URL scan complete. Report saved.');
      } catch (error) {
        showToast(error.message);
      } finally {
        setSubmitBusy(urlForm, false);
      }
    });
  }

  if (uploadForm) {
    uploadForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      const formData = new FormData(uploadForm);
      const file = formData.get('file');

      if (!file || !(file instanceof File)) {
        showToast('Choose a file to upload');
        return;
      }

      renderPendingReportMessage(output, 'File');
      setSubmitBusy(uploadForm, true, 'Uploading...');

      try {
        const response = await fetch(`${API_BASE}/analyze/upload`, {
          method: 'POST',
          headers: {
            ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {})
          },
          body: formData
        });

        const data = await response.json().catch(() => ({}));
        if (!response.ok) {
          throw new Error(data.message || 'Upload analysis failed');
        }

        renderSavedReportMessage(output, data);
        showToast('File analysis complete. Report saved.');
      } catch (error) {
        showToast(error.message);
      } finally {
        setSubmitBusy(uploadForm, false);
      }
    });
  }
}

function wireReportPage() {
  const titleNode = document.querySelector('[data-report-title]');
  const bodyNode = document.querySelector('[data-report-body]');
  const filtersRoot = document.querySelector('[data-report-filters]');
  const paginationRoot = document.querySelector('[data-report-pagination]');
  const firstButton = document.querySelector('[data-report-first]');
  const prevButton = document.querySelector('[data-report-prev]');
  const nextButton = document.querySelector('[data-report-next]');
  const lastButton = document.querySelector('[data-report-last]');
  const pageInfoNode = document.querySelector('[data-report-page-info]');
  const pageNumbersNode = document.querySelector('[data-report-page-buttons]');
  const pageSizeNode = document.querySelector('[data-report-page-size]');
  const loadingNode = document.querySelector('[data-report-loading]');
  const searchNode = document.querySelector('[data-report-search]');
  const iocFilterNode = document.querySelector('[data-report-ioc-filter]');
  const riskFilterNode = document.querySelector('[data-report-risk-filter]');
  const params = new URLSearchParams(window.location.search);
  const id = params.get('id');

  if (!titleNode || !bodyNode) return;

  if (!getToken()) {
    window.location.href = 'login.html?next=report.html';
    return;
  }

  const fetchReports = (filters) => {
    return requestJSON(`${API_BASE}/analyze/reports${buildReportsQueryParams(filters)}`);
  };

  fetchReports(id ? { reportId: id, limit: 1 } : { limit: 20, offset: 0 })
    .then((data) => {
      if (!id) {
        titleNode.textContent = 'Reports';
        if (filtersRoot) {
          filtersRoot.hidden = false;
        }
        if (paginationRoot) {
          paginationRoot.hidden = false;
        }

        const state = {
          offset: 0,
          limit: pageSizeNode ? Number(pageSizeNode.value || 20) : 20,
          total: 0,
          query: '',
          iocType: 'all',
          risk: 'all',
          isLoading: false
        };

        const setLoadingState = (isLoading) => {
          state.isLoading = isLoading;

          if (loadingNode) {
            loadingNode.hidden = !isLoading;
          }

          if (pageSizeNode) {
            pageSizeNode.disabled = isLoading;
          }

          if (firstButton) firstButton.disabled = isLoading || state.offset <= 0;
          if (prevButton) prevButton.disabled = isLoading || state.offset <= 0;
          if (nextButton) nextButton.disabled = isLoading || (state.offset + state.limit) >= state.total;
          if (lastButton) lastButton.disabled = isLoading || (state.offset + state.limit) >= state.total;
        };

        const parseReportListStateFromUrl = () => {
          const currentParams = new URLSearchParams(window.location.search);
          const query = String(currentParams.get('q') || '').trim();
          const iocType = String(currentParams.get('iocType') || 'all').toLowerCase();
          const risk = String(currentParams.get('risk') || 'all').toLowerCase();
          const pageSize = Number(currentParams.get('pageSize') || 20);
          const safeLimit = [10, 20, 50].includes(pageSize) ? pageSize : 20;
          const page = Number(currentParams.get('page') || 1);

          return {
            query,
            iocType: ['all', 'urls', 'ips', 'domains', 'hashes'].includes(iocType) ? iocType : 'all',
            risk: ['all', 'high', 'moderate', 'low'].includes(risk) ? risk : 'all',
            limit: safeLimit,
            offset: Math.max(0, (Number.isFinite(page) && page > 0 ? Math.floor(page) - 1 : 0) * safeLimit)
          };
        };

        const readInitialStateFromUrl = () => {
          const parsed = parseReportListStateFromUrl();

          state.query = parsed.query;
          state.iocType = parsed.iocType;
          state.risk = parsed.risk;
          state.limit = parsed.limit;
          state.offset = parsed.offset;

          if (searchNode) searchNode.value = state.query;
          if (iocFilterNode) iocFilterNode.value = state.iocType;
          if (riskFilterNode) riskFilterNode.value = state.risk;
          if (pageSizeNode) pageSizeNode.value = String(state.limit);
        };

        const syncReportListStateToUrl = (historyMode = 'push') => {
          if (historyMode === 'none') {
            return;
          }

          const nextParams = new URLSearchParams();
          const currentPage = Math.floor(state.offset / state.limit) + 1;

          if (state.query) nextParams.set('q', state.query);
          if (state.iocType !== 'all') nextParams.set('iocType', state.iocType);
          if (state.risk !== 'all') nextParams.set('risk', state.risk);
          if (state.limit !== 20) nextParams.set('pageSize', String(state.limit));
          if (currentPage > 1) nextParams.set('page', String(currentPage));

          const nextQuery = nextParams.toString();
          const nextUrl = `${window.location.pathname}${nextQuery ? `?${nextQuery}` : ''}`;
          const currentUrl = `${window.location.pathname}${window.location.search}`;
          if (nextUrl === currentUrl) {
            return;
          }

          if (historyMode === 'replace') {
            window.history.replaceState({}, '', nextUrl);
            return;
          }

          window.history.pushState({}, '', nextUrl);
        };

        const getTotalPages = () => {
          if (!state.total || !state.limit) {
            return 0;
          }

          return Math.ceil(state.total / state.limit);
        };

        const renderPageButtons = () => {
          if (!pageNumbersNode) {
            return;
          }

          const totalPages = getTotalPages();
          if (totalPages <= 1) {
            pageNumbersNode.innerHTML = '';
            return;
          }

          const currentPage = Math.floor(state.offset / state.limit) + 1;
          const maxButtons = 5;
          let startPage = Math.max(1, currentPage - Math.floor(maxButtons / 2));
          let endPage = Math.min(totalPages, startPage + maxButtons - 1);

          if ((endPage - startPage + 1) < maxButtons) {
            startPage = Math.max(1, endPage - maxButtons + 1);
          }

          const pages = [];
          for (let page = startPage; page <= endPage; page += 1) {
            pages.push(page);
          }

          pageNumbersNode.innerHTML = pages
            .map((page) => `
              <button
                class="inline-link report-page-button ${page === currentPage ? 'is-active' : ''}"
                type="button"
                data-report-page="${page}">
                ${page}
              </button>
            `)
            .join('');

          pageNumbersNode.querySelectorAll('[data-report-page]').forEach((button) => {
            button.addEventListener('click', () => {
              const page = Number(button.getAttribute('data-report-page'));
              if (!Number.isFinite(page) || page < 1) {
                return;
              }

              state.offset = (page - 1) * state.limit;
              applyCurrentFilters();
            });
          });
        };

        const updatePageInfo = (returnedCount) => {
          const start = state.total ? state.offset + 1 : 0;
          const end = state.total ? Math.min(state.offset + returnedCount, state.total) : 0;
          if (pageInfoNode) {
            const currentPage = state.total ? Math.floor(state.offset / state.limit) + 1 : 0;
            const totalPages = getTotalPages();
            pageInfoNode.textContent = `Showing ${start}-${end} of ${state.total}${totalPages ? ` (Page ${currentPage}/${totalPages})` : ''}`;
          }

          if (prevButton) {
            prevButton.disabled = state.isLoading || state.offset <= 0;
          }

          if (firstButton) {
            firstButton.disabled = state.isLoading || state.offset <= 0;
          }

          if (nextButton) {
            nextButton.disabled = state.isLoading || (state.offset + state.limit) >= state.total;
          }

          if (lastButton) {
            lastButton.disabled = state.isLoading || (state.offset + state.limit) >= state.total;
          }

          renderPageButtons();
        };

        const renderReportsList = (reportsToRender) => {
          if (!reportsToRender.length) {
            bodyNode.innerHTML = '<p class="muted">No reports match your current filters.</p>';
            updatePageInfo(0);
            return;
          }

          bodyNode.innerHTML = `
            <div class="list">
              ${reportsToRender
                .map((report) => {
                  const risk = getRiskDisplay(report);
                  const mitreAttack = Array.isArray(report.metadata?.mitreAttack) ? report.metadata.mitreAttack : [];
                  return `
                    <div class="list-item">
                      <div class="section-head" style="margin-bottom:8px;">
                        <strong>${report.title}</strong>
                        <span class="badge ${risk.badgeClass}">${risk.badgeText}</span>
                      </div>
                      <p class="muted">${report.sourceType || 'text'}${report.sourceValue ? ` · ${report.sourceValue}` : ''}</p>
                      <p class="muted">Created: ${report.createdAt ? new Date(report.createdAt).toLocaleString() : 'Unknown'}</p>
                      <p class="muted">${risk.statusText}</p>
                      <p class="muted">IOCs: ${report.metadata?.iocIntel?.counts?.total || 0} · High confidence: ${report.metadata?.iocIntel?.highConfidenceCount || 0}</p>
                      <p class="muted">MITRE: ${mitreAttack.length ? mitreAttack.map((item) => item.id).join(', ') : 'None'}</p>
                      <a class="inline-link" href="report.html?id=${report.id}">Open details</a>
                      <button class="inline-link inline-link-danger" type="button" data-delete-report-id="${report.id}">Delete</button>
                    </div>
                  `;
                })
                .join('')}
            </div>
          `;

          bodyNode.querySelectorAll('[data-delete-report-id]').forEach((button) => {
            button.addEventListener('click', async () => {
              const reportId = button.getAttribute('data-delete-report-id');
              if (!reportId) {
                return;
              }

              const shouldDelete = await showConfirmModal({
                title: 'Delete report',
                message: 'This report will be permanently removed.',
                confirmText: 'Delete'
              });

              if (!shouldDelete) {
                return;
              }

              try {
                await requestJSON(`${API_BASE}/analyze/reports/${reportId}`, { method: 'DELETE' });
                if (state.offset > 0 && data.reports.length === 1) {
                  state.offset = Math.max(0, state.offset - state.limit);
                }
                applyCurrentFilters({ historyMode: 'replace' });
                showToast('Report deleted');
              } catch (error) {
                showToast(error.message);
              }
            });
          });

          updatePageInfo(reportsToRender.length);
        };

        const renderReportsSkeleton = (count = 4) => {
          const cards = Array.from({ length: count }, () => `
            <div class="report-skeleton-card">
              <div class="report-skeleton-line is-title"></div>
              <div class="report-skeleton-line is-meta"></div>
              <div class="report-skeleton-line is-meta"></div>
              <div class="report-skeleton-line is-short"></div>
            </div>
          `).join('');

          bodyNode.innerHTML = `<div class="report-skeleton-list">${cards}</div>`;
        };

        const getSkeletonCountForLimit = (limit) => {
          const normalizedLimit = Number(limit || 0);
          if (normalizedLimit <= 10) {
            return 4;
          }

          if (normalizedLimit <= 20) {
            return 6;
          }

          if (normalizedLimit <= 50) {
            return 8;
          }

          return 8;
        };

        const getFilters = () => ({
          query: searchNode ? searchNode.value : '',
          iocType: iocFilterNode ? iocFilterNode.value : 'all',
          risk: riskFilterNode ? riskFilterNode.value : 'all',
          limit: state.limit,
          offset: state.offset
        });

        const applyCurrentFilters = async (options = {}) => {
          const allowOffsetCorrection = options.allowOffsetCorrection !== false;
          const historyMode = options.historyMode || 'push';
          const showSkeleton = options.showSkeleton !== false;
          const currentFilters = getFilters();
          state.query = currentFilters.query;
          state.iocType = currentFilters.iocType;
          state.risk = currentFilters.risk;
          syncReportListStateToUrl(historyMode);
          setLoadingState(true);
          if (showSkeleton) {
            renderReportsSkeleton(getSkeletonCountForLimit(state.limit));
          }

          try {
            const filteredData = await fetchReports({
              q: currentFilters.query,
              iocType: currentFilters.iocType,
              risk: currentFilters.risk,
              limit: currentFilters.limit,
              offset: currentFilters.offset
            });
            data.reports = filteredData.reports || [];
            state.total = Number(filteredData.pagination?.total || 0);

            if (allowOffsetCorrection && state.total > 0 && state.offset >= state.total) {
              const lastPageOffset = Math.max(0, (Math.ceil(state.total / state.limit) - 1) * state.limit);
              if (lastPageOffset !== state.offset) {
                state.offset = lastPageOffset;
                return applyCurrentFilters({ allowOffsetCorrection: false, historyMode: 'replace', showSkeleton: false });
              }
            }

            renderReportsList(data.reports);
          } catch (error) {
            bodyNode.innerHTML = `<p class="muted">${error.message}</p>`;
            updatePageInfo(0);
          } finally {
            setLoadingState(false);
          }
        };

        const resetToFirstPageAndApply = () => {
          state.offset = 0;
          applyCurrentFilters({ historyMode: 'push' });
        };

        const debouncedResetToFirstPageAndApply = debounce(resetToFirstPageAndApply, 250);

        if (searchNode) {
          searchNode.addEventListener('input', debouncedResetToFirstPageAndApply);
        }
        if (iocFilterNode) {
          iocFilterNode.addEventListener('change', resetToFirstPageAndApply);
        }
        if (riskFilterNode) {
          riskFilterNode.addEventListener('change', resetToFirstPageAndApply);
        }
        if (pageSizeNode) {
          pageSizeNode.addEventListener('change', () => {
            const nextLimit = Number(pageSizeNode.value || 20);
            state.limit = Number.isFinite(nextLimit) && nextLimit > 0 ? nextLimit : 20;
            state.offset = 0;
            applyCurrentFilters({ historyMode: 'push' });
          });
        }

        if (prevButton) {
          prevButton.addEventListener('click', () => {
            if (state.isLoading) {
              return;
            }

            if (state.offset <= 0) {
              return;
            }

            state.offset = Math.max(0, state.offset - state.limit);
            applyCurrentFilters({ historyMode: 'push' });
          });
        }

        if (firstButton) {
          firstButton.addEventListener('click', () => {
            if (state.isLoading) {
              return;
            }

            if (state.offset <= 0) {
              return;
            }

            state.offset = 0;
            applyCurrentFilters({ historyMode: 'push' });
          });
        }

        if (nextButton) {
          nextButton.addEventListener('click', () => {
            if (state.isLoading) {
              return;
            }

            if ((state.offset + state.limit) >= state.total) {
              return;
            }

            state.offset += state.limit;
            applyCurrentFilters({ historyMode: 'push' });
          });
        }

        if (lastButton) {
          lastButton.addEventListener('click', () => {
            if (state.isLoading) {
              return;
            }

            if (state.total <= 0) {
              return;
            }

            state.offset = Math.max(0, (Math.ceil(state.total / state.limit) - 1) * state.limit);
            applyCurrentFilters({ historyMode: 'push' });
          });
        }

        window.addEventListener('popstate', () => {
          readInitialStateFromUrl();
          applyCurrentFilters({ historyMode: 'none' });
        });

        if (!data.reports.length) {
          bodyNode.innerHTML = '<p class="muted">No reports available yet. Run an analysis first.</p>';
          updatePageInfo(0);
          return;
        }

        readInitialStateFromUrl();
        setLoadingState(true);
        applyCurrentFilters({ historyMode: 'replace' });
        return;
      }

      const report = (data.reports || []).find((item) => item.id === id);
      if (!report) {
        titleNode.textContent = 'Report not found';
        bodyNode.innerHTML = '<p class="muted">The requested report could not be located.</p>';
        return;
      }

      titleNode.textContent = report.title;
      const risk = getRiskDisplay(report);
      const mitreAttack = Array.isArray(report.metadata?.mitreAttack) ? report.metadata.mitreAttack : [];
      const riskProfile = getRiskProfile(report);
      bodyNode.innerHTML = `
        <div class="list">
          <div class="list-item"><strong>Status:</strong> <span class="badge ${risk.badgeClass}">${risk.badgeText}</span> ${risk.statusText}</div>
          <div class="list-item"><strong>Summary:</strong> ${report.summary}</div>
          <div class="list-item"><strong>Risk drivers:</strong> ${riskProfile.topDrivers.length ? riskProfile.topDrivers.join(', ') : 'No structured risk factors available'}</div>
          <div class="list-item"><strong>Source:</strong> ${report.sourceType || 'text'}${report.sourceValue ? ` · ${report.sourceValue}` : ''}</div>
          <div class="list-item"><strong>Storage:</strong> ${report.artifactPath || 'No artifact stored'}</div>
          <div class="list-item"><strong>Findings:</strong> ${report.findings.map((finding) => `${finding.title} (${finding.severity})`).join(', ') || 'None'}</div>
          <div class="list-item"><strong>IOC summary:</strong> ${report.metadata?.iocIntel?.counts?.total || 0} total (${report.metadata?.iocIntel?.counts?.urls || 0} URLs, ${report.metadata?.iocIntel?.counts?.ips || 0} IPs, ${report.metadata?.iocIntel?.counts?.domains || 0} domains, ${report.metadata?.iocIntel?.counts?.hashes || 0} hashes)</div>
          <div class="list-item"><strong>High-confidence IOCs:</strong> ${report.metadata?.iocIntel?.highConfidenceCount || 0}</div>
          <div class="list-item"><strong>External intel:</strong> ${report.metadata?.iocIntel?.externalSummary ? `VT ${report.metadata.iocIntel.externalSummary.virusTotalEnabled ? 'enabled' : 'disabled'}, AbuseIPDB ${report.metadata.iocIntel.externalSummary.abuseIpdbEnabled ? 'enabled' : 'disabled'}, malicious matches ${report.metadata.iocIntel.externalSummary.maliciousExternalMatches || 0}` : 'No external enrichment summary'}</div>
          <div class="list-item"><strong>MITRE ATT&CK:</strong> ${mitreAttack.length ? mitreAttack.map((item) => `${item.id} ${item.name} [${item.tactic}]`).join(', ') : 'No mapped techniques'}</div>
          <div class="list-item"><strong>Recommendations:</strong> ${report.recommendations.join(' ')}</div>
          <div class="list-item"><strong>Metadata:</strong> ${report.metadata && Object.keys(report.metadata).length ? JSON.stringify(report.metadata) : 'None'}</div>
          <div class="list-item"><strong>Created:</strong> ${new Date(report.createdAt).toLocaleString()}</div>
          <div class="list-item">
            <div class="classification-export-controls">
              <label>
                Classification for export
                <select data-export-pdf-classification>
                  <option value="confidential" selected>Confidential</option>
                  <option value="internal">Internal</option>
                  <option value="public">Public</option>
                </select>
              </label>
              <div class="classification-watermark-meta">
                <div class="classification-watermark-badge" data-watermark-mode-badge>Watermark mode: Loading...</div>
                <span class="muted classification-watermark-checked" data-watermark-mode-checked>Last checked: --</span>
              </div>
              <div class="classification-tooltip-wrap">
                <button class="inline-link" type="button" data-classification-info-toggle aria-expanded="false" aria-controls="classification-impact-panel">Preview classification impact</button>
                <div class="classification-tooltip-panel" id="classification-impact-panel" data-classification-info-panel hidden>
                  <strong data-classification-impact-heading>Confidential export</strong>
                  <p class="muted" data-classification-impact-watermark>CONFIDENTIAL watermark is applied (or your watermark override).</p>
                  <p class="muted" data-classification-impact-footer>Footer shows classification as Confidential with organization and generated-by details.</p>
                  <div class="classification-legend" aria-label="Watermark mode color legend">
                    <span class="classification-legend-item"><span class="classification-legend-dot is-confidential"></span>Confidential</span>
                    <span class="classification-legend-item"><span class="classification-legend-dot is-internal"></span>Internal</span>
                    <span class="classification-legend-item"><span class="classification-legend-dot is-public"></span>Public</span>
                    <span class="classification-legend-item"><span class="classification-legend-dot is-override"></span>Override</span>
                    <span class="classification-legend-item"><span class="classification-legend-dot is-disabled"></span>Disabled</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
          <div class="list-item">
            <button class="inline-link" type="button" data-export-pdf-report-id="${report.id}" data-export-pdf-mode="full">Download Executive PDF</button>
            <button class="inline-link" type="button" data-export-pdf-report-id="${report.id}" data-export-pdf-mode="brief">Download One-Page Brief PDF</button>
            <div class="muted pdf-generated-hint" data-export-pdf-last-full>Executive PDF last generated: never</div>
            <div class="muted pdf-generated-hint" data-export-pdf-last-brief>Brief PDF last generated: never</div>
            <div class="muted pdf-generated-hint" data-export-pdf-running-time hidden>Generating PDF... 0s elapsed</div>
          </div>
          <div class="list-item">
            <button class="inline-link inline-link-danger" type="button" data-delete-report-id="${report.id}">Delete this report</button>
          </div>
        </div>
      `;

      const exportButtons = [...bodyNode.querySelectorAll('[data-export-pdf-report-id]')];
      const fullGeneratedHintNode = bodyNode.querySelector('[data-export-pdf-last-full]');
      const briefGeneratedHintNode = bodyNode.querySelector('[data-export-pdf-last-brief]');
      const runningTimeHintNode = bodyNode.querySelector('[data-export-pdf-running-time]');
      const pdfGenerationHistory = getPdfGenerationHistory(report.id);
      let isPdfGenerationInProgress = false;
      let pdfGenerationStartedAt = 0;
      let pdfGenerationTimer = null;

      const buttonOriginalLabels = new Map(
        exportButtons.map((button) => [button, button.textContent || 'Download PDF'])
      );

      const clearPdfGenerationTimer = () => {
        if (pdfGenerationTimer) {
          window.clearInterval(pdfGenerationTimer);
          pdfGenerationTimer = null;
        }
      };

      const updateRunningTimeHint = (modeLabel) => {
        if (!runningTimeHintNode || !pdfGenerationStartedAt) {
          return;
        }

        const elapsedSeconds = Math.max(0, Math.floor((Date.now() - pdfGenerationStartedAt) / 1000));
        runningTimeHintNode.hidden = false;
        runningTimeHintNode.textContent = `Generating ${modeLabel}... ${elapsedSeconds}s elapsed`;
      };

      const updatePdfGenerationHints = () => {
        if (fullGeneratedHintNode) {
          fullGeneratedHintNode.textContent = `Executive PDF last generated: ${pdfGenerationHistory.full ? new Date(pdfGenerationHistory.full).toLocaleString() : 'never'}`;
        }

        if (briefGeneratedHintNode) {
          briefGeneratedHintNode.textContent = `Brief PDF last generated: ${pdfGenerationHistory.brief ? new Date(pdfGenerationHistory.brief).toLocaleString() : 'never'}`;
        }
      };

      updatePdfGenerationHints();

      exportButtons.forEach((exportButton) => {
        exportButton.addEventListener('click', async () => {
          if (isPdfGenerationInProgress) {
            showToast('PDF generation is already running. Please wait.');
            return;
          }

          const reportId = exportButton.getAttribute('data-export-pdf-report-id');
          const exportMode = exportButton.getAttribute('data-export-pdf-mode') || 'full';
          const classificationNode = bodyNode.querySelector('[data-export-pdf-classification]');
          const exportClassification = classificationNode ? classificationNode.value : 'confidential';
          if (!reportId) {
            return;
          }

          isPdfGenerationInProgress = true;
          pdfGenerationStartedAt = Date.now();
          exportButtons.forEach((button) => {
            button.disabled = true;
          });

          const modeLabel = exportMode === 'brief' ? 'Brief PDF' : 'Executive PDF';
          exportButton.textContent = exportMode === 'brief' ? 'Generating Brief...' : 'Generating PDF...';
          updateRunningTimeHint(modeLabel);
          clearPdfGenerationTimer();
          pdfGenerationTimer = window.setInterval(() => updateRunningTimeHint(modeLabel), 1000);

          try {
            await downloadExecutiveReportPdf(reportId, exportMode, exportClassification);
            if (exportMode === 'brief') {
              pdfGenerationHistory.brief = Date.now();
            } else {
              pdfGenerationHistory.full = Date.now();
            }
            setPdfGenerationHistory(reportId, pdfGenerationHistory);
            updatePdfGenerationHints();
            if (runningTimeHintNode) {
              const totalSeconds = Math.max(0, Math.floor((Date.now() - pdfGenerationStartedAt) / 1000));
              runningTimeHintNode.hidden = false;
              runningTimeHintNode.textContent = `${modeLabel} generated in ${totalSeconds}s`;
            }
            showToast(exportMode === 'brief' ? 'Leadership brief downloaded' : 'Executive PDF downloaded');
          } catch (error) {
            if (runningTimeHintNode) {
              const totalSeconds = Math.max(0, Math.floor((Date.now() - pdfGenerationStartedAt) / 1000));
              runningTimeHintNode.hidden = false;
              runningTimeHintNode.textContent = `Generation failed after ${totalSeconds}s. Try again.`;
            }
            showToast(error.message);
          } finally {
            isPdfGenerationInProgress = false;
            clearPdfGenerationTimer();
            pdfGenerationStartedAt = 0;
            exportButtons.forEach((button) => {
              button.disabled = false;
              button.textContent = buttonOriginalLabels.get(button) || button.textContent;
            });
          }
        });
      });

      const classificationNode = bodyNode.querySelector('[data-export-pdf-classification]');
      const tooltipToggleButton = bodyNode.querySelector('[data-classification-info-toggle]');
      const tooltipPanel = bodyNode.querySelector('[data-classification-info-panel]');
      const impactHeadingNode = bodyNode.querySelector('[data-classification-impact-heading]');
      const impactWatermarkNode = bodyNode.querySelector('[data-classification-impact-watermark]');
      const impactFooterNode = bodyNode.querySelector('[data-classification-impact-footer]');
      const watermarkModeBadgeNode = bodyNode.querySelector('[data-watermark-mode-badge]');
      const watermarkModeCheckedNode = bodyNode.querySelector('[data-watermark-mode-checked]');
      const watermarkConfigState = {
        source: 'classification',
        text: null,
        checkedAt: 0
      };

      const updateWatermarkModeBadge = () => {
        if (!watermarkModeBadgeNode) {
          return;
        }

        const modeLabel = getWatermarkModeLabel(watermarkConfigState.source);
        const badgeToneClass = getWatermarkBadgeToneClass(
          watermarkConfigState.source,
          classificationNode ? classificationNode.value : 'confidential'
        );

        watermarkModeBadgeNode.textContent = `Watermark mode: ${modeLabel}`;
        watermarkModeBadgeNode.classList.remove('is-confidential', 'is-internal', 'is-public', 'is-override', 'is-disabled');
        watermarkModeBadgeNode.classList.add(badgeToneClass);

        if (watermarkModeCheckedNode) {
          const elapsedText = formatElapsedTimeShort(watermarkConfigState.checkedAt);
          watermarkModeCheckedNode.textContent = `Last checked: ${elapsedText}`;
        }
      };

      const updateClassificationImpact = () => {
        const impact = getClassificationImpact(classificationNode ? classificationNode.value : 'confidential', watermarkConfigState);
        if (impactHeadingNode) impactHeadingNode.textContent = impact.heading;
        if (impactWatermarkNode) impactWatermarkNode.textContent = impact.watermark;
        if (impactFooterNode) impactFooterNode.textContent = impact.footer;
        updateWatermarkModeBadge();
      };

      if (classificationNode) {
        classificationNode.addEventListener('change', updateClassificationImpact);
      }

      const closeImpactTooltip = () => {
        if (!tooltipPanel || !tooltipToggleButton) {
          return;
        }

        tooltipPanel.hidden = true;
        tooltipToggleButton.setAttribute('aria-expanded', 'false');
      };

      if (tooltipToggleButton && tooltipPanel) {
        tooltipToggleButton.addEventListener('click', () => {
          const shouldOpen = tooltipPanel.hidden;
          tooltipPanel.hidden = !shouldOpen;
          tooltipToggleButton.setAttribute('aria-expanded', shouldOpen ? 'true' : 'false');
          if (shouldOpen) {
            updateClassificationImpact();
          }
        });

        bodyNode.addEventListener('click', (event) => {
          const target = event.target;
          if (!(target instanceof Element)) {
            return;
          }

          if (!target.closest('[data-classification-info-toggle]') && !target.closest('[data-classification-info-panel]')) {
            closeImpactTooltip();
          }
        });

        window.addEventListener('keydown', (event) => {
          if (event.key === 'Escape') {
            closeImpactTooltip();
          }
        });
      }

      const cachedPdfConfig = getCachedPdfConfig();
      if (cachedPdfConfig?.value?.watermark) {
        watermarkConfigState.source = String(cachedPdfConfig.value.watermark.source || 'classification').toLowerCase();
        watermarkConfigState.text = cachedPdfConfig.value.watermark.text || null;
        watermarkConfigState.checkedAt = Number(cachedPdfConfig.checkedAt || 0) || Date.now();
      }
      updateClassificationImpact();

      if (window.__acaWatermarkCheckedTimer) {
        window.clearInterval(window.__acaWatermarkCheckedTimer);
      }
      window.__acaWatermarkCheckedTimer = window.setInterval(updateWatermarkModeBadge, 1000);

      requestJSON(`${API_BASE}/analyze/pdf-config`)
        .then((config) => {
          if (config?.watermark) {
            watermarkConfigState.source = String(config.watermark.source || 'classification').toLowerCase();
            watermarkConfigState.text = config.watermark.text || null;
            watermarkConfigState.checkedAt = Date.now();
            setCachedPdfConfig(config);
          }
          updateClassificationImpact();
        })
        .catch(() => {
          updateClassificationImpact();
        });

      const deleteButton = bodyNode.querySelector('[data-delete-report-id]');
      if (deleteButton) {
        deleteButton.addEventListener('click', async () => {
          const reportId = deleteButton.getAttribute('data-delete-report-id');
          if (!reportId) {
            return;
          }

          const shouldDelete = await showConfirmModal({
            title: 'Delete report',
            message: 'This report will be permanently removed.',
            confirmText: 'Delete'
          });

          if (!shouldDelete) {
            return;
          }

          try {
            await requestJSON(`${API_BASE}/analyze/reports/${reportId}`, { method: 'DELETE' });
            showToast('Report deleted');
            window.location.href = 'report.html';
          } catch (error) {
            showToast(error.message);
          }
        });
      }
    })
    .catch((error) => {
      titleNode.textContent = 'Error loading report';
      bodyNode.innerHTML = `<p class="muted">${error.message}</p>`;
    });
}

function wireMitrePage() {
  const matrixNode = document.querySelector('[data-mitre-matrix]');
  const summaryNode = document.querySelector('[data-mitre-summary]');
  const filtersRoot = document.querySelector('[data-mitre-filters]');
  const tacticFilterNode = document.querySelector('[data-mitre-tactic-filter]');
  const severityFilterNode = document.querySelector('[data-mitre-severity-filter]');
  const historyFilterNode = document.querySelector('[data-mitre-history-filter]');

  if (!matrixNode || !summaryNode) {
    return;
  }

  if (!getToken()) {
    window.location.href = 'login.html?next=mitre.html';
    return;
  }

  requestJSON(`${API_BASE}/analyze/reports${buildReportsQueryParams({ limit: 100, offset: 0 })}`)
    .then((data) => {
      const allReports = Array.isArray(data.reports) ? data.reports : [];
      const state = {
        tactic: 'all',
        severity: 'all',
        history: 'all'
      };

      const deriveMitreFromFindings = (findings) => {
        const entries = [];
        const findingList = Array.isArray(findings) ? findings : [];

        findingList.forEach((finding) => {
          const title = String(finding?.title || '').toLowerCase();
          const severity = String(finding?.severity || 'low').toLowerCase();

          if (title.includes('weak authentication')) {
            entries.push({ id: 'T1078', name: 'Valid Accounts', tactic: 'Persistence', severity, confidence: 0.72, score: 18, reasons: ['Derived from weak authentication finding'] });
            entries.push({ id: 'T1110', name: 'Brute Force', tactic: 'Credential Access', severity, confidence: 0.66, score: 14, reasons: ['Derived from weak authentication finding'] });
          }

          if (title.includes('injection')) {
            entries.push({ id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access', severity, confidence: 0.78, score: 20, reasons: ['Derived from injection finding'] });
            entries.push({ id: 'T1059', name: 'Command and Scripting Interpreter', tactic: 'Execution', severity, confidence: 0.7, score: 16, reasons: ['Derived from injection finding'] });
          }

          if (title.includes('sensitive data exposure')) {
            entries.push({ id: 'T1552', name: 'Unsecured Credentials', tactic: 'Credential Access', severity, confidence: 0.8, score: 19, reasons: ['Derived from sensitive data exposure finding'] });
          }

          if (title.includes('unsafe transport')) {
            entries.push({ id: 'T1071.001', name: 'Web Protocols', tactic: 'Command and Control', severity, confidence: 0.68, score: 14, reasons: ['Derived from unsafe transport finding'] });
          }

          if (title.includes('suspicious process')) {
            entries.push({ id: 'T1059', name: 'Command and Scripting Interpreter', tactic: 'Execution', severity, confidence: 0.74, score: 17, reasons: ['Derived from suspicious process finding'] });
          }
        });

        return entries;
      };

      const getReportTechniques = (report) => {
        const mapped = Array.isArray(report?.metadata?.mitreAttack) ? report.metadata.mitreAttack : [];
        if (mapped.length) {
          return mapped;
        }

        return deriveMitreFromFindings(report?.findings);
      };

      const getHistoryCutoff = (historyValue) => {
        const now = Date.now();
        if (historyValue === '7d') return now - (7 * 24 * 60 * 60 * 1000);
        if (historyValue === '30d') return now - (30 * 24 * 60 * 60 * 1000);
        if (historyValue === '90d') return now - (90 * 24 * 60 * 60 * 1000);
        return null;
      };

      const aggregateTechniques = (reports) => {
        const techniqueMap = new Map();

        reports.forEach((report) => {
          const reportCreatedAt = report.createdAt ? new Date(report.createdAt).toISOString() : null;
          const techniques = getReportTechniques(report);

          techniques.forEach((technique) => {
            if (!technique?.id) {
              return;
            }

            const key = String(technique.id);
            if (!techniqueMap.has(key)) {
              techniqueMap.set(key, {
                id: technique.id,
                name: technique.name || 'Unknown technique',
                tactic: technique.tactic || 'Unknown',
                severity: String(technique.severity || 'low').toLowerCase(),
                maxConfidence: Number(technique.confidence || 0),
                weightedScore: Number(technique.score || 0),
                count: 0,
                reasons: [],
                lastSeen: reportCreatedAt
              });
            }

            const entry = techniqueMap.get(key);
            entry.count += 1;
            entry.maxConfidence = Math.max(entry.maxConfidence, Number(technique.confidence || 0));
            entry.weightedScore += Number(technique.score || 0);

            const severityRank = { high: 3, medium: 2, low: 1 };
            const nextSeverity = String(technique.severity || 'low').toLowerCase();
            if ((severityRank[nextSeverity] || 1) > (severityRank[entry.severity] || 1)) {
              entry.severity = nextSeverity;
            }

            if (reportCreatedAt && (!entry.lastSeen || reportCreatedAt > entry.lastSeen)) {
              entry.lastSeen = reportCreatedAt;
            }

            const reasonList = Array.isArray(technique.reasons) ? technique.reasons : [];
            reasonList.forEach((reason) => {
              if (reason && !entry.reasons.includes(reason)) {
                entry.reasons.push(reason);
              }
            });
          });
        });

        return [...techniqueMap.values()].sort((a, b) => {
          if (b.weightedScore !== a.weightedScore) {
            return b.weightedScore - a.weightedScore;
          }
          return b.count - a.count;
        });
      };

      const buildTacticOptions = (reports) => {
        if (!tacticFilterNode) {
          return;
        }

        const tacticSet = new Set();
        reports.forEach((report) => {
          const techniques = getReportTechniques(report);
          techniques.forEach((technique) => {
            tacticSet.add(String(technique?.tactic || 'Unknown'));
          });
        });

        const sortedTactics = [...tacticSet].filter(Boolean).sort((a, b) => a.localeCompare(b));
        tacticFilterNode.innerHTML = `
          <option value="all">All tactics</option>
          ${sortedTactics.map((tactic) => `<option value="${tactic}">${tactic}</option>`).join('')}
        `;
      };

      const filterReportsByHistory = (reports, historyValue) => {
        const cutoff = getHistoryCutoff(historyValue);
        if (!cutoff) {
          return reports;
        }

        return reports.filter((report) => {
          const createdAt = report.createdAt ? Date.parse(report.createdAt) : NaN;
          return Number.isFinite(createdAt) && createdAt >= cutoff;
        });
      };

      const render = () => {
        const reportsInWindow = filterReportsByHistory(allReports, state.history);
        const techniques = aggregateTechniques(reportsInWindow).filter((technique) => {
          if (state.tactic !== 'all' && technique.tactic !== state.tactic) {
            return false;
          }

          if (state.severity !== 'all' && technique.severity !== state.severity) {
            return false;
          }

          return true;
        });

        const tacticMap = new Map();
        techniques.forEach((item) => {
          tacticMap.set(item.tactic, (tacticMap.get(item.tactic) || 0) + 1);
        });

        summaryNode.innerHTML = `
          <div class="dashboard-grid">
            <div class="card"><h3>Techniques observed</h3><div class="metric"><strong>${techniques.length}</strong></div></div>
            <div class="card"><h3>Tactics covered</h3><div class="metric"><strong>${tacticMap.size}</strong></div></div>
            <div class="card"><h3>Weighted confidence</h3><div class="metric"><strong>${Math.round(techniques.reduce((sum, item) => sum + item.maxConfidence, 0) * 100)}</strong><span>%</span></div></div>
          </div>
        `;

        if (!techniques.length) {
          matrixNode.innerHTML = '<div class="list-item">No MITRE techniques match these filters.</div>';
          return;
        }

        matrixNode.innerHTML = `
          <div class="list">
            ${techniques
              .map((technique) => {
                const severityBadgeClass = technique.severity === 'high'
                  ? 'danger'
                  : technique.severity === 'medium'
                    ? 'warn'
                    : 'success';

                return `
                  <div class="list-item">
                    <div class="section-head" style="margin-bottom:8px;">
                      <strong>${technique.id} · ${technique.name}</strong>
                      <span class="badge ${severityBadgeClass}">${technique.severity.toUpperCase()}</span>
                    </div>
                    <p class="muted">Tactic: ${technique.tactic}</p>
                    <p class="muted">Occurrences: ${technique.count} · Weighted score: ${Math.round(technique.weightedScore)} · Max confidence: ${Math.round(technique.maxConfidence * 100)}%</p>
                    <p class="muted">Last seen: ${technique.lastSeen ? new Date(technique.lastSeen).toLocaleString() : 'Unknown'}</p>
                    <p class="muted">Reasons: ${technique.reasons.length ? technique.reasons.join('; ') : 'No reasons captured'}</p>
                  </div>
                `;
              })
              .join('')}
          </div>
        `;
      };

      buildTacticOptions(allReports);
      if (filtersRoot) {
        filtersRoot.hidden = false;
      }

      if (tacticFilterNode) {
        tacticFilterNode.addEventListener('change', () => {
          state.tactic = tacticFilterNode.value || 'all';
          render();
        });
      }

      if (severityFilterNode) {
        severityFilterNode.addEventListener('change', () => {
          state.severity = severityFilterNode.value || 'all';
          render();
        });
      }

      if (historyFilterNode) {
        historyFilterNode.addEventListener('change', () => {
          state.history = historyFilterNode.value || 'all';
          render();
        });
      }

      render();
    })
    .catch((error) => {
      summaryNode.innerHTML = '';
      matrixNode.innerHTML = `<div class="list-item">${error.message}</div>`;
    });
}

document.addEventListener('DOMContentLoaded', () => {
  wireAuthForms();
  wireNav();
  renderDashboard();
  wireAnalyzer();
  wireReportPage();
  wireMitrePage();
});
