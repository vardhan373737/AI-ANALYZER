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

function wireAuthForms() {
  const loginForm = document.querySelector('[data-login-form]');
  const registerForm = document.querySelector('[data-register-form]');

  if (loginForm) {
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
        window.location.href = 'dashboard.html';
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
        window.location.href = 'dashboard.html';
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
      window.location.href = 'index.html';
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
  output.innerHTML = `
    <div class="result-grid">
      <div><strong>Threat Type:</strong> ${analysis.threatType || (analysis.riskLevel === 'High' ? 'Phishing / Scam' : analysis.riskLevel === 'Moderate' ? 'Suspicious' : 'Safe')}</div>
      <div><strong>Risk Level:</strong> ${analysis.riskLevel || 'Unknown'}${analysis.riskScore !== undefined ? ` (${analysis.riskScore}/100)` : ''}</div>
      <div><strong>Explanation:</strong> ${analysis.explanation || 'Analysis completed on server.'}</div>
      <div><strong>Indicators:</strong> ${(analysis.findings || []).map((item) => item.title).join(', ') || 'None found'}</div>
      <div><strong>Recommendations:</strong> ${(analysis.recommendations || []).join(' ') || 'No recommendations available.'}</div>
      <div><strong>Report:</strong> Saved on server. View it in <a class="inline-link" href="report.html">Reports</a>.</div>
      ${report.id ? `<div><a class="inline-link" href="report.html?id=${report.id}">Open this report</a></div>` : ''}
    </div>
  `;
}

function renderDashboard() {
  const nameNode = document.querySelector('[data-user-name]');
  const roleNode = document.querySelector('[data-user-role]');
  const tokenNode = document.querySelector('[data-token-state]');
  const reportList = document.querySelector('[data-report-list]');

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
    requestJSON(`${API_BASE}/analyze/reports`)
      .then((data) => {
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
  const params = new URLSearchParams(window.location.search);
  const id = params.get('id');

  if (!titleNode || !bodyNode) return;

  requestJSON(`${API_BASE}/analyze/reports`)
    .then((data) => {
      if (!id) {
        titleNode.textContent = 'Reports';

        if (!data.reports.length) {
          bodyNode.innerHTML = '<p class="muted">No reports available yet. Run an analysis first.</p>';
          return;
        }

        bodyNode.innerHTML = `
          <div class="list">
            ${data.reports
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
              button.closest('.list-item')?.remove();
              if (!bodyNode.querySelector('.list-item')) {
                bodyNode.innerHTML = '<p class="muted">No reports available yet. Run an analysis first.</p>';
              }
              showToast('Report deleted');
            } catch (error) {
              showToast(error.message);
            }
          });
        });
        return;
      }

      const report = data.reports.find((item) => item.id === id);
      if (!report) {
        titleNode.textContent = 'Report not found';
        bodyNode.innerHTML = '<p class="muted">The requested report could not be located.</p>';
        return;
      }

      titleNode.textContent = report.title;
      const risk = getRiskDisplay(report.summary);
      bodyNode.innerHTML = `
        <div class="list">
          <div class="list-item"><strong>Status:</strong> <span class="badge ${risk.badgeClass}">${risk.badgeText}</span> ${risk.statusText}</div>
          <div class="list-item"><strong>Summary:</strong> ${report.summary}</div>
          <div class="list-item"><strong>Source:</strong> ${report.sourceType || 'text'}${report.sourceValue ? ` · ${report.sourceValue}` : ''}</div>
          <div class="list-item"><strong>Storage:</strong> ${report.artifactPath || 'No artifact stored'}</div>
          <div class="list-item"><strong>Findings:</strong> ${report.findings.map((finding) => `${finding.title} (${finding.severity})`).join(', ') || 'None'}</div>
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

document.addEventListener('DOMContentLoaded', () => {
  wireAuthForms();
  wireNav();
  renderDashboard();
  wireAnalyzer();
  wireReportPage();
});
