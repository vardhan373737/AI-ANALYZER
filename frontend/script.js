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

function getRiskDisplay(summary) {
  const summaryText = String(summary || '');
  const levelMatch = summaryText.match(/Risk\s*level:\s*(High|Moderate|Low)/i);
  const scoreMatch = summaryText.match(/\((\d+\/100)\)/i);

  const level = levelMatch ? levelMatch[1].toLowerCase() : 'low';
  const score = scoreMatch ? ` (${scoreMatch[1]})` : '';

  if (level === 'high') {
    return {
      badgeClass: 'danger',
      badgeText: `Danger${score}`,
      statusText: 'High risk detected. Treat this as potentially malicious.'
    };
  }

  if (level === 'moderate') {
    return {
      badgeClass: 'warn',
      badgeText: `Needs Review${score}`,
      statusText: 'Moderate risk. Review carefully before trusting it.'
    };
  }

  return {
    badgeClass: 'success',
    badgeText: `Safe${score}`,
    statusText: 'Looks good. No strong malicious indicators were found.'
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
  const mitreAttack = analysis.mitreAttack || report.metadata?.mitreAttack || [];
  output.innerHTML = `
    <div class="result-grid">
      <div><strong>Threat Type:</strong> ${analysis.threatType || (analysis.riskLevel === 'High' ? 'Phishing / Scam' : analysis.riskLevel === 'Moderate' ? 'Suspicious' : 'Safe')}</div>
      <div><strong>Risk Level:</strong> ${analysis.riskLevel || 'Unknown'}${analysis.riskScore !== undefined ? ` (${analysis.riskScore}/100)` : ''}</div>
      <div><strong>Explanation:</strong> ${analysis.explanation || 'Analysis completed on server.'}</div>
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
  const summary = String(report?.summary || '').toLowerCase();
  if (summary.includes('risk level: high')) {
    return 'high';
  }
  if (summary.includes('risk level: moderate')) {
    return 'moderate';
  }
  return 'low';
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

  if (reportList) {
    requestJSON(`${API_BASE}/analyze/reports${buildReportsQueryParams({ limit: 100, offset: 0 })}`)
      .then((data) => {
        const iocMetrics = aggregateIocMetrics(data.reports || []);

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
                const risk = getRiskDisplay(report.summary);
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
                  const risk = getRiskDisplay(report.summary);
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
      const risk = getRiskDisplay(report.summary);
      const mitreAttack = Array.isArray(report.metadata?.mitreAttack) ? report.metadata.mitreAttack : [];
      bodyNode.innerHTML = `
        <div class="list">
          <div class="list-item"><strong>Status:</strong> <span class="badge ${risk.badgeClass}">${risk.badgeText}</span> ${risk.statusText}</div>
          <div class="list-item"><strong>Summary:</strong> ${report.summary}</div>
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
            <button class="inline-link inline-link-danger" type="button" data-delete-report-id="${report.id}">Delete this report</button>
          </div>
        </div>
      `;

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

  if (!matrixNode || !summaryNode) {
    return;
  }

  if (!getToken()) {
    window.location.href = 'login.html?next=mitre.html';
    return;
  }

  requestJSON(`${API_BASE}/analyze/reports${buildReportsQueryParams({ limit: 100, offset: 0 })}`)
    .then((data) => {
      const techniqueMap = new Map();
      const tacticMap = new Map();

      (data.reports || []).forEach((report) => {
        const techniques = Array.isArray(report.metadata?.mitreAttack) ? report.metadata.mitreAttack : [];
        techniques.forEach((technique) => {
          if (!technique?.id) {
            return;
          }

          const key = technique.id;
          if (!techniqueMap.has(key)) {
            techniqueMap.set(key, {
              ...technique,
              count: 0
            });
          }

          const entry = techniqueMap.get(key);
          entry.count += 1;

          const tactic = technique.tactic || 'Unknown';
          tacticMap.set(tactic, (tacticMap.get(tactic) || 0) + 1);
        });
      });

      const techniques = [...techniqueMap.values()].sort((a, b) => b.count - a.count);
      const tactics = [...tacticMap.entries()].sort((a, b) => b[1] - a[1]);

      summaryNode.innerHTML = `
        <div class="dashboard-grid">
          <div class="card"><h3>Techniques observed</h3><div class="metric"><strong>${techniques.length}</strong></div></div>
          <div class="card"><h3>Tactics covered</h3><div class="metric"><strong>${tactics.length}</strong></div></div>
          <div class="card"><h3>Total mappings</h3><div class="metric"><strong>${techniques.reduce((sum, item) => sum + item.count, 0)}</strong></div></div>
        </div>
      `;

      if (!techniques.length) {
        matrixNode.innerHTML = '<div class="list-item">No MITRE mappings yet. Run analyses to populate this matrix.</div>';
        return;
      }

      matrixNode.innerHTML = `
        <div class="list">
          ${techniques
            .map((technique) => `
              <div class="list-item">
                <div class="section-head" style="margin-bottom:8px;">
                  <strong>${technique.id} · ${technique.name}</strong>
                  <span class="badge warn">Seen ${technique.count} time${technique.count > 1 ? 's' : ''}</span>
                </div>
                <p class="muted">Tactic: ${technique.tactic || 'Unknown'}</p>
                <p class="muted">Reasons: ${Array.isArray(technique.reasons) && technique.reasons.length ? technique.reasons.join('; ') : 'No reasons captured'}</p>
              </div>
            `)
            .join('')}
        </div>
      `;
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
