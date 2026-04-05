const PDFDocument = require('pdfkit');

// CSS-style design tokens for PDF rendering (applied in specific render functions below).
const PDF_THEME = {
  colors: {
    ink900: '#0f172a',
    ink700: '#334155',
    ink500: '#64748b',
    page: '#f8fafc',
    white: '#ffffff',
    brandPrimary: '#0b1f3a',
    brandAccent: '#0ea5e9',
    strategyAccent: '#0b5cab',
    strategySoft: '#eaf3ff',
    technicalAccent: '#0f766e',
    technicalSoft: '#e8f7f4',
    line: '#dbe4ef',
    riskHigh: '#b91c1c',
    riskModerate: '#b45309',
    riskLow: '#15803d'
  },
  font: {
    body: 11,
    small: 9,
    h1: 30,
    h2: 18,
    h3: 12
  },
  layout: {
    margin: 50,
    footerHeight: 34,
    topBarHeight: 120,
    maxBodyY: 736
  }
};

const ONE_LINE_CHAR_BUDGET = 110;

function riskColor(level) {
  const normalized = String(level || '').toLowerCase();
  if (normalized === 'high') return PDF_THEME.colors.riskHigh;
  if (normalized === 'moderate') return PDF_THEME.colors.riskModerate;
  return PDF_THEME.colors.riskLow;
}

function safeText(value, fallback = 'N/A') {
  const text = String(value ?? '')
    .replace(/\s+/g, ' ')
    .trim();
  return text || fallback;
}

function ensureSpace(doc, neededHeight = 60) {
  if (doc.y + neededHeight > PDF_THEME.layout.maxBodyY) {
    doc.addPage();
  }
}

function compactSummary(value, mode = 'full') {
  const raw = safeText(value, 'No summary available');
  const sentenceLimit = mode === 'snapshot' ? 2 : mode === 'brief' ? 2 : 3;
  const charLimit = mode === 'snapshot' ? 240 : mode === 'brief' ? 360 : 560;
  const segments = raw.match(/[^.!?]+[.!?]?/g) || [raw];
  const compact = segments.slice(0, sentenceLimit).join(' ').trim();
  if (compact.length <= charLimit) {
    return compact;
  }
  return `${compact.slice(0, charLimit - 3).trim()}...`;
}

function toOneLineBulletText(value, maxChars = ONE_LINE_CHAR_BUDGET) {
  const text = safeText(value);
  if (text.length <= maxChars) {
    return text;
  }
  return `${text.slice(0, Math.max(3, maxChars - 3)).trim()}...`;
}

function drawMetricTable(doc, { x, y, width, rowHeight, items, columns }) {
  const safeColumns = Math.max(1, Number(columns) || 1);
  const rows = Math.ceil(items.length / safeColumns);
  const tableHeight = rows * rowHeight;
  const colWidth = width / safeColumns;

  doc.rect(x, y, width, tableHeight).fill('#f8fafc').lineWidth(1).stroke(PDF_THEME.colors.line);

  for (let col = 1; col < safeColumns; col += 1) {
    const colX = x + col * colWidth;
    doc.moveTo(colX, y).lineTo(colX, y + tableHeight).stroke(PDF_THEME.colors.line);
  }

  for (let row = 1; row < rows; row += 1) {
    const rowY = y + row * rowHeight;
    doc.moveTo(x, rowY).lineTo(x + width, rowY).stroke(PDF_THEME.colors.line);
  }

  items.forEach((item, idx) => {
    const col = idx % safeColumns;
    const row = Math.floor(idx / safeColumns);
    const cellX = x + col * colWidth;
    const cellY = y + row * rowHeight;
    const accentX = cellX + 8;
    const accentY = cellY + 8;

    doc.roundedRect(accentX, accentY, 4, rowHeight - 16, 2).fill(item.color || PDF_THEME.colors.brandAccent);
    doc.font('Helvetica').fontSize(8).fillColor(PDF_THEME.colors.ink500).text(String(item.label || '').toUpperCase(), cellX + 18, cellY + 9, {
      width: colWidth - 24,
      lineBreak: false,
      ellipsis: true
    });
    doc.font('Helvetica-Bold').fontSize(13).fillColor(PDF_THEME.colors.ink900).text(String(item.value || '0'), cellX + 18, cellY + 22, {
      width: colWidth - 24,
      lineBreak: false,
      ellipsis: true
    });
  });

  return y + tableHeight;
}

function sectionToneColors(tone = 'strategy') {
  if (tone === 'technical') {
    return {
      accent: PDF_THEME.colors.technicalAccent,
      soft: PDF_THEME.colors.technicalSoft
    };
  }

  return {
    accent: PDF_THEME.colors.strategyAccent,
    soft: PDF_THEME.colors.strategySoft
  };
}

function buildLeadershipDecisions({ mappedReport, risk, topMitre, iocCounts }) {
  const decisions = [];
  const topTechnique = Array.isArray(topMitre) && topMitre.length ? topMitre[0] : null;
  const secondTechnique = Array.isArray(topMitre) && topMitre.length > 1 ? topMitre[1] : null;
  const totalIocs = Number(iocCounts?.total || 0);
  const findings = Array.isArray(mappedReport?.findings) ? mappedReport.findings : [];
  const highFindings = findings.filter((item) => String(item?.severity || '').toLowerCase() === 'high').length;

  decisions.push(`Treat this report as ${safeText(risk?.level, 'Moderate')} priority with a risk score of ${Number.isFinite(risk?.score) ? risk.score : 'N/A'}/100.`);
  if (topTechnique) {
    decisions.push(`Prioritize controls for ${safeText(topTechnique.id)} ${safeText(topTechnique.name, 'Unknown technique')} (${safeText(topTechnique.severity, 'Low')} severity).`);
  }
  if (secondTechnique) {
    decisions.push(`Assign SOC validation for ${safeText(secondTechnique.id)} ${safeText(secondTechnique.name, 'Unknown technique')} within this reporting cycle.`);
  }
  decisions.push(`Direct SOC triage to validate and contain ${totalIocs} detected indicators across perimeter controls.`);
  if (highFindings > 0) {
    decisions.push(`Escalate ${highFindings} high-severity findings to incident response leadership for immediate tracking.`);
  }

  const recommendations = Array.isArray(mappedReport?.recommendations) ? mappedReport.recommendations : [];
  recommendations.forEach((recommendation) => {
    if (decisions.length < 5) {
      decisions.push(safeText(recommendation));
    }
  });

  while (decisions.length < 5) {
    decisions.push('Maintain daily executive status updates until risk trend is reduced.');
  }

  return decisions.slice(0, 5).map((decision) => toOneLineBulletText(decision));
}

function drawMitreMatrix(doc, techniques) {
  const items = Array.isArray(techniques) ? techniques.slice(0, 8) : [];
  if (!items.length) {
    doc.font('Helvetica').fontSize(10).fillColor(PDF_THEME.colors.ink500).text('No MITRE techniques were mapped for this report.');
    return;
  }

  const columnWidth = 244;
  const gap = 12;
  const rowHeight = 74;
  const rows = Math.ceil(items.length / 2);

  for (let row = 0; row < rows; row += 1) {
    ensureSpace(doc, rowHeight + 12);
    const baseY = doc.y;

    for (let column = 0; column < 2; column += 1) {
      const idx = row * 2 + column;
      if (idx >= items.length) {
        continue;
      }

      const item = items[idx];
      const x = 50 + (column * (columnWidth + gap));
      const tone = riskColor(item.severity);

      doc.roundedRect(x, baseY, columnWidth, rowHeight, 6).fill('#f8fafc').lineWidth(1).stroke(PDF_THEME.colors.line);
      doc.roundedRect(x + 8, baseY + 8, 5, rowHeight - 16, 2).fill(tone);

      doc.font('Helvetica-Bold').fontSize(9.6).fillColor(PDF_THEME.colors.ink900).text(`${safeText(item.id)} ${safeText(item.name, 'Unknown')}`, x + 20, baseY + 8, {
        width: columnWidth - 28,
        lineBreak: false,
        ellipsis: true
      });

      doc.font('Helvetica').fontSize(8.6).fillColor(tone).text(`${safeText(item.severity, 'Low')} | ${Math.round(Number(item.confidence || 0) * 100)}% confidence`, x + 20, baseY + 24, {
        width: columnWidth - 28,
        lineBreak: false,
        ellipsis: true
      });

      doc.font('Helvetica').fontSize(8.2).fillColor(PDF_THEME.colors.ink500).text(`Tactic: ${safeText(item.tactic, 'Unknown tactic')}`, x + 20, baseY + 39, {
        width: columnWidth - 28,
        lineBreak: false,
        ellipsis: true
      });
    }

    doc.y = baseY + rowHeight + 10;
  }

  doc.moveDown(0.3);
}

function drawWatermark(doc, label) {
  const text = safeText(label, 'CONFIDENTIAL');
  const previousY = doc.y;
  const centerX = doc.page.width / 2;
  const centerY = doc.page.height / 2;

  doc.save();
  doc.rotate(-35, { origin: [centerX, centerY] });
  doc.fillColor('#94a3b8', 0.12);
  doc.font('Helvetica-Bold').fontSize(58).text(text.toUpperCase(), 0, centerY - 30, {
    width: doc.page.width,
    align: 'center',
    lineBreak: false,
    ellipsis: true
  });
  doc.restore();

  doc.y = previousY;
}

function drawHeader(doc, title, mode) {
  const t = PDF_THEME;

  doc.rect(0, 0, doc.page.width, t.layout.topBarHeight).fill(t.colors.brandPrimary);
  doc.rect(0, t.layout.topBarHeight, doc.page.width, 3).fill(t.colors.brandAccent);

  doc.font('Helvetica-Bold').fontSize(16).fillColor(t.colors.white).text('Kith Security', 50, 25);
  doc.font('Helvetica').fontSize(9).fillColor('#bfdbfe').text(mode === 'brief' ? 'Leadership Brief' : 'Executive Report', 50, 45);

  doc.font('Helvetica-Bold').fontSize(11).fillColor('#dbeafe').text(safeText(title, 'Security Report').slice(0, 72), 50, 70, {
    width: doc.page.width - 100,
    ellipsis: true
  });

  doc.y = 138;
}

function drawFooter(doc, context) {
  const t = PDF_THEME;
  const previousY = doc.y;
  const footerTextY = doc.page.height - doc.page.margins.bottom - 16;
  const footerBandY = footerTextY - 8;
  const classColor = riskColor(context.classification);

  doc.rect(0, footerBandY, doc.page.width, 24).fill('#eef4fb');
  doc.moveTo(40, footerBandY).lineTo(doc.page.width - 40, footerBandY).stroke(t.colors.line);

  const left = [
    safeText(context.organizationName, 'Organization'),
    safeText(context.generatedBy, 'Analyst')
  ].join(' | ');

  doc.font('Helvetica').fontSize(7.5).fillColor(t.colors.ink500).text(left, 50, footerTextY, {
    width: 260,
    align: 'left',
    lineBreak: false,
    ellipsis: true
  });

  doc.font('Helvetica-Bold').fontSize(7.5).fillColor(classColor).text(`[${safeText(context.classification, 'CONFIDENTIAL').toUpperCase()}]`, doc.page.width / 2 - 42, footerTextY, {
    width: 84,
    align: 'center',
    lineBreak: false,
    ellipsis: true
  });

  const right = [
    context.reportId ? `ID:${String(context.reportId).slice(0, 8)}` : null,
    safeText(context.generatedAt, '').split(' ')[0]
  ].filter(Boolean).join(' | ');

  doc.font('Helvetica').fontSize(7.5).fillColor(t.colors.ink500).text(right, doc.page.width - 250, footerTextY, {
    width: 200,
    align: 'right',
    lineBreak: false,
    ellipsis: true
  });

  doc.y = previousY;
}

function writeSectionTitle(doc, title, tone = 'strategy') {
  const t = PDF_THEME;
  const toneColors = sectionToneColors(tone);
  ensureSpace(doc, 68);

  doc.moveDown(0.7);
  doc.roundedRect(50, doc.y - 2, 500, 30, 6).fill(toneColors.soft);
  doc.roundedRect(56, doc.y + 6, 5, 14, 2).fill(toneColors.accent);
  doc.font('Helvetica-Bold').fontSize(t.font.h2).fillColor(t.colors.ink900).text(title, 68, doc.y + 2, {
    width: 480,
    lineBreak: false,
    ellipsis: true
  });
  doc.moveDown(0.6);
}

function renderLeadershipSnapshot(doc, input) {
  const { mappedReport, risk, topMitre, iocCounts } = input;
  const t = PDF_THEME;
  const decisions = buildLeadershipDecisions({ mappedReport, risk, topMitre, iocCounts });

  doc.rect(50, 58, 500, 76).fill('#eef6ff').lineWidth(1).stroke('#c9e0ff');
  doc.font('Helvetica-Bold').fontSize(20).fillColor(t.colors.strategyAccent).text('Leadership Snapshot', 70, 78);
  doc.font('Helvetica').fontSize(9.5).fillColor(t.colors.ink700).text('Top 5 decisions for executive action', 72, 104);

  const summaryBlockY = 160;
  doc.roundedRect(50, summaryBlockY, 500, 72, 8).fill('#f8fafc').lineWidth(1).stroke(t.colors.line);
  doc.font('Helvetica-Bold').fontSize(10).fillColor(t.colors.ink900).text('Current Situation', 66, summaryBlockY + 14);
  doc.font('Helvetica').fontSize(9.5).fillColor(t.colors.ink700).text(compactSummary(mappedReport.summary, 'snapshot'), 66, summaryBlockY + 30, {
    width: 468,
    lineGap: 2
  });

  let y = 252;
  decisions.forEach((decision, idx) => {
    const boxHeight = 44;
    doc.roundedRect(50, y, 500, boxHeight, 7).fill(idx % 2 === 0 ? '#ffffff' : '#f8fbff').lineWidth(1).stroke('#d8e6f7');
    doc.roundedRect(62, y + 10, 24, 24, 4).fill(t.colors.strategyAccent);
    doc.font('Helvetica-Bold').fontSize(10).fillColor('#ffffff').text(String(idx + 1), 71, y + 16);
    doc.font('Helvetica-Bold').fontSize(10).fillColor(t.colors.ink900).text(decision, 96, y + 14, {
      width: 438,
      lineBreak: false,
      ellipsis: true
    });
    y += boxHeight + 10;
  });
}

function renderCoverPage(doc, payload) {
  const t = PDF_THEME;

  doc.rect(0, 0, doc.page.width, doc.page.height).fill(t.colors.white);
  doc.rect(0, 0, doc.page.width, 260).fill(t.colors.brandPrimary);
  doc.rect(0, 260, doc.page.width, 3).fill(t.colors.brandAccent);

  doc.font('Helvetica-Bold').fontSize(20).fillColor(t.colors.white).text('Kith Security', 50, 34);
  doc.font('Helvetica').fontSize(10).fillColor('#bfdbfe').text('Executive Threat Assessment', 50, 60);

  doc.moveTo(50, 94).lineTo(doc.page.width - 50, 94).stroke('#bfdbfe').lineWidth(1);

  doc.font('Helvetica-Bold').fontSize(t.font.h1).fillColor(t.colors.white).text(safeText(payload.title, 'Security Report'), 50, 112, {
    width: doc.page.width - 100,
    ellipsis: true
  });

  const riskTone = riskColor(payload.riskLevel);
  const classTone = riskColor(payload.classification);

  doc.rect(50, 190, 230, 58).fill('#f8fafc').lineWidth(1.5).stroke(riskTone);
  doc.font('Helvetica').fontSize(8).fillColor(t.colors.ink500).text('THREAT LEVEL', 62, 200);
  doc.font('Helvetica-Bold').fontSize(19).fillColor(riskTone).text(safeText(payload.riskLabel), 62, 214);

  doc.rect(300, 190, 230, 58).fill('#f8fafc').lineWidth(1.5).stroke(classTone);
  doc.font('Helvetica').fontSize(8).fillColor(t.colors.ink500).text('CLASSIFICATION', 312, 200);
  doc.font('Helvetica-Bold').fontSize(19).fillColor(classTone).text(safeText(payload.classification), 312, 214);

  doc.font('Helvetica-Bold').fontSize(11).fillColor(t.colors.ink900).text('Report Details', 50, 305);

  const rows = [
    ['Organization', safeText(payload.organizationName)],
    ['Prepared By', safeText(payload.generatedBy)],
    ['Created At', safeText(payload.createdAtLabel)],
    ['Document ID', safeText(payload.reportId).slice(0, 16)]
  ];

  rows.forEach((row, idx) => {
    const y = 330 + (idx * 19);
    doc.font('Helvetica').fontSize(8).fillColor(t.colors.ink500).text(row[0].toUpperCase(), 50, y);
    doc.font('Helvetica-Bold').fontSize(9.5).fillColor(t.colors.ink700).text(row[1], 170, y);
  });

  doc.rect(0, doc.page.height - 82, doc.page.width, 82).fill('#eef4fb');
  doc.moveTo(0, doc.page.height - 82).lineTo(doc.page.width, doc.page.height - 82).stroke(t.colors.line).lineWidth(1);
  doc.font('Helvetica-Bold').fontSize(9.5).fillColor(t.colors.ink900).text('CONFIDENTIALITY NOTICE', 50, doc.page.height - 70);
  doc.font('Helvetica').fontSize(8).fillColor(t.colors.ink500).text('This report contains sensitive cybersecurity intelligence. Share only with authorized recipients and handle according to internal security policy.', 50, doc.page.height - 54, {
    width: doc.page.width - 100,
    lineGap: 1
  });
}

function renderBriefBody(doc, input) {
  const { mappedReport, risk, iocCounts, topMitre } = input;
  const t = PDF_THEME;

  writeSectionTitle(doc, 'Executive Summary', 'strategy');
  doc.font('Helvetica').fontSize(10.8).fillColor(t.colors.ink700).text(compactSummary(mappedReport.summary, 'brief'), {
    width: 500,
    lineGap: 2.2
  });

  writeSectionTitle(doc, 'Metrics Snapshot', 'strategy');
  ensureSpace(doc, 72);
  const metricsY = doc.y;
  const cards = [
    { label: 'Risk', value: `${risk.level}${Number.isFinite(risk.score) ? ` (${risk.score}/100)` : ''}`, color: riskColor(risk.level) },
    { label: 'IOCs', value: `${Number(iocCounts.total || 0)}`, color: t.colors.brandAccent },
    { label: 'High Conf', value: `${Number(mappedReport.metadata?.iocIntel?.highConfidenceCount || 0)}`, color: '#7c3aed' }
  ];

  doc.y = drawMetricTable(doc, {
    x: 50,
    y: metricsY,
    width: 500,
    rowHeight: 52,
    items: cards,
    columns: 3
  }) + 8;

  writeSectionTitle(doc, 'Top Threat Techniques', 'technical');
  const top = Array.isArray(topMitre) ? topMitre.slice(0, 4) : [];
  if (!top.length) {
    doc.font('Helvetica').fontSize(9.4).fillColor(t.colors.ink500).text('No MITRE techniques mapped.');
  } else {
    top.forEach((item) => {
      ensureSpace(doc, 30);
      const tone = riskColor(item.severity);
      doc.font('Helvetica-Bold').fontSize(10.2).fillColor(t.colors.ink900).text(`${toOneLineBulletText(`${safeText(item.id, 'T-NA')} ${safeText(item.name, 'Unknown')}`)}`, {
        width: 500,
        lineBreak: false,
        ellipsis: true
      });
      doc.font('Helvetica').fontSize(8.8).fillColor(tone).text(`${safeText(item.severity, 'Low')} | ${Math.round(Number(item.confidence || 0) * 100)}% confidence`, {
        indent: 12,
        lineBreak: false,
        ellipsis: true
      });
      doc.moveDown(0.25);
    });
  }

  writeSectionTitle(doc, 'Recommended Actions', 'strategy');
  const actions = Array.isArray(mappedReport.recommendations) ? mappedReport.recommendations.slice(0, 4) : [];
  if (!actions.length) {
    doc.font('Helvetica').fontSize(9.4).fillColor(t.colors.ink500).text('No recommendations provided.');
  } else {
    actions.forEach((action, idx) => {
      ensureSpace(doc, 22);
      doc.font('Helvetica-Bold').fontSize(9.8).fillColor(t.colors.ink900).text(`${idx + 1}. ${toOneLineBulletText(action)}`, {
        width: 500,
        lineBreak: false,
        ellipsis: true
      });
      doc.moveDown(0.25);
    });
  }
}

function renderFullBody(doc, input) {
  const { mappedReport, risk, iocCounts, topMitre } = input;
  const t = PDF_THEME;

  writeSectionTitle(doc, 'Executive Summary', 'strategy');
  doc.font('Helvetica').fontSize(t.font.body).fillColor(t.colors.ink700).text(compactSummary(mappedReport.summary, 'full'), {
    width: 500,
    lineGap: 2.8
  });

  writeSectionTitle(doc, 'Risk Assessment', 'strategy');
  ensureSpace(doc, 60);
  const tone = riskColor(risk.level);
  const y = doc.y;
  doc.rect(50, y, 220, 42).fill('#f8fafc').lineWidth(1.5).stroke(tone);
  doc.font('Helvetica').fontSize(8.5).fillColor(t.colors.ink500).text('THREAT LEVEL', 60, y + 7);
  doc.font('Helvetica-Bold').fontSize(16).fillColor(tone).text(`${risk.level}${Number.isFinite(risk.score) ? ` (${risk.score}/100)` : ''}`, 60, y + 20);
  doc.font('Helvetica').fontSize(10).fillColor(t.colors.ink500).text(`Source: ${safeText(mappedReport.sourceType)}${mappedReport.sourceValue ? ` - ${mappedReport.sourceValue}` : ''}`, 290, y + 14, {
    width: 250
  });
  doc.y = y + 50;

  writeSectionTitle(doc, 'MITRE ATT&CK Techniques', 'technical');
  drawMitreMatrix(doc, topMitre);

  writeSectionTitle(doc, 'Indicator Statistics', 'technical');
  ensureSpace(doc, 120);
  const metricCards = [
    { label: 'Total', value: iocCounts.total || 0, color: t.colors.brandAccent },
    { label: 'URLs', value: iocCounts.urls || 0, color: '#2563eb' },
    { label: 'IPs', value: iocCounts.ips || 0, color: '#b45309' },
    { label: 'Domains', value: iocCounts.domains || 0, color: '#7c3aed' },
    { label: 'Hashes', value: iocCounts.hashes || 0, color: '#db2777' }
  ];

  doc.y = drawMetricTable(doc, {
    x: 50,
    y: doc.y,
    width: 500,
    rowHeight: 52,
    items: metricCards,
    columns: 3
  }) + 10;

  writeSectionTitle(doc, 'Recommended Actions', 'strategy');
  const actions = Array.isArray(mappedReport.recommendations) ? mappedReport.recommendations.slice(0, 8) : [];
  if (!actions.length) {
    doc.font('Helvetica').fontSize(10).fillColor(t.colors.ink500).text('No recommendations were provided for this report.');
  } else {
    actions.forEach((action, idx) => {
      ensureSpace(doc, 24);
      doc.font('Helvetica-Bold').fontSize(10).fillColor(t.colors.ink900).text(`${idx + 1}. ${toOneLineBulletText(action)}`, {
        width: 500,
        lineBreak: false,
        ellipsis: true
      });
      doc.moveDown(0.25);
    });
  }

  writeSectionTitle(doc, 'Detailed Findings', 'technical');
  const findings = Array.isArray(mappedReport.findings) ? mappedReport.findings.slice(0, 12) : [];
  if (!findings.length) {
    doc.font('Helvetica').fontSize(10).fillColor(t.colors.ink500).text('No findings were recorded.');
  } else {
    findings.forEach((finding, idx) => {
      ensureSpace(doc, 26);
      const toneFinding = riskColor(finding.severity);
      doc.font('Helvetica-Bold').fontSize(10).fillColor(t.colors.ink900).text(`${idx + 1}. ${toOneLineBulletText(safeText(finding.title, 'Untitled finding'))}`, {
        width: 500,
        lineBreak: false,
        ellipsis: true
      });
      doc.font('Helvetica').fontSize(9).fillColor(toneFinding).text(`${safeText(finding.severity, 'Low')} | Count: ${Number(finding.count || 1)}`, {
        indent: 10,
        lineBreak: false,
        ellipsis: true
      });
      doc.moveDown(0.2);
    });
  }
}

async function streamStyledReportPdf({
  res,
  filename,
  mappedReport,
  mode,
  classification,
  watermarkText,
  organizationName,
  generatedBy,
  generatedAtLabel,
  risk,
  iocCounts,
  topMitre
}) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ size: 'A4', margin: PDF_THEME.layout.margin });

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

    doc.on('error', reject);
    res.on('error', reject);
    res.on('finish', resolve);

    doc.pipe(res);

    const decoratePage = (showHeader) => {
      drawWatermark(doc, watermarkText);
      if (showHeader) {
        drawHeader(doc, mappedReport.title, mode);
      }
      drawFooter(doc, {
        organizationName,
        generatedBy,
        classification,
        reportId: mappedReport.id,
        generatedAt: generatedAtLabel
      });
    };

    let autoHeaderForNewPages = mode !== 'brief';
    let pageEventLock = false;

    doc.on('pageAdded', () => {
      if (pageEventLock) {
        return;
      }
      pageEventLock = true;
      try {
        decoratePage(autoHeaderForNewPages);
      } finally {
        pageEventLock = false;
      }
    });

    if (mode === 'brief') {
      decoratePage(true);
      renderBriefBody(doc, { mappedReport, risk, iocCounts, topMitre });
    } else {
      autoHeaderForNewPages = false;
      drawWatermark(doc, watermarkText);
      renderCoverPage(doc, {
        organizationName,
        title: mappedReport.title,
        riskLabel: `${risk.level}${Number.isFinite(risk.score) ? ` (${risk.score}/100)` : ''}`,
        riskLevel: risk.level,
        classification,
        generatedBy,
        createdAtLabel: mappedReport.createdAt ? new Date(mappedReport.createdAt).toLocaleString() : 'Unknown',
        reportId: mappedReport.id
      });
      drawFooter(doc, {
        organizationName,
        generatedBy,
        classification,
        reportId: mappedReport.id,
        generatedAt: generatedAtLabel
      });

      doc.addPage();
      renderLeadershipSnapshot(doc, { mappedReport, risk, topMitre, iocCounts });

      autoHeaderForNewPages = true;
      doc.addPage();
      renderFullBody(doc, { mappedReport, risk, iocCounts, topMitre });
    }

    doc.end();
  });
}

module.exports = {
  PDF_THEME,
  streamStyledReportPdf
};
