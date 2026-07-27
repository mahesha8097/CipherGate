// services/reportGenerator.js
// Builds the structured JSON report and renders a PDF version with PDFKit.

const fs = require('fs');
const path = require('path');
const PDFDocument = require('pdfkit');
const { formatDate } = require('../utils/helpers');

const REPORTS_DIR = process.env.REPORTS_DIR || path.join(__dirname, '..', 'reports');

function buildJsonReport(auditData) {
  const { auditId, targetUrl, scoreResult, moduleResults, startedAt } = auditData;

  const severityOrder = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
  const sortedFailed = [...scoreResult.failedChecks].sort(
    (a, b) => severityOrder[a.severity] - severityOrder[b.severity]
  );

  return {
    auditId,
    website: targetUrl,
    auditDate: formatDate(startedAt),
    executiveSummary: buildExecutiveSummary(targetUrl, scoreResult),
    riskScore: {
      value: scoreResult.score,
      rating: scoreResult.label,
      color: scoreResult.color,
    },
    stats: {
      totalChecks: scoreResult.totalChecks,
      passed: scoreResult.passedCount,
      failed: scoreResult.failedCount,
    },
    passedChecks: scoreResult.passedChecks.map(formatCheck),
    failedChecks: sortedFailed.map(formatCheck),
    informationalNotes: scoreResult.infoChecks.map(formatCheck),
    modules: moduleResults.map((m) => ({
      module: m.module,
      checks: m.findings.length,
      passed: m.findings.filter((f) => f.passed).length,
    })),
    generatedAt: new Date().toISOString(),
  };
}

function formatCheck(check) {
  return {
    module: check.module,
    name: check.name,
    severity: check.severity,
    status: check.passed ? 'Pass' : 'Fail',
    detail: check.detail,
    recommendation: check.recommendation,
  };
}

function buildExecutiveSummary(targetUrl, scoreResult) {
  const criticalCount = scoreResult.failedChecks.filter((f) => f.severity === 'Critical').length;
  const highCount = scoreResult.failedChecks.filter((f) => f.severity === 'High').length;

  return (
    `This audit evaluated the authentication security posture of ${targetUrl} across ${scoreResult.totalChecks} checks ` +
    `spanning transport security, cookie handling, headers, CSRF protection, JWT usage, CAPTCHA, and MFA availability. ` +
    `The site achieved an overall security score of ${scoreResult.score}/100 (${scoreResult.label}), with ` +
    `${scoreResult.passedCount} check(s) passed and ${scoreResult.failedCount} check(s) failed` +
    `${criticalCount || highCount ? `, including ${criticalCount} critical and ${highCount} high-severity issue(s) that warrant prompt remediation.` : '.'}`
  );
}

function ensureReportsDir() {
  if (!fs.existsSync(REPORTS_DIR)) {
    fs.mkdirSync(REPORTS_DIR, { recursive: true });
  }
}

function saveJsonReport(jsonReport) {
  ensureReportsDir();
  const filePath = path.join(REPORTS_DIR, `${jsonReport.auditId}.json`);
  fs.writeFileSync(filePath, JSON.stringify(jsonReport, null, 2));
  return filePath;
}

const SEVERITY_COLORS = {
  Critical: '#FF3B3B',
  High: '#FF8C00',
  Medium: '#FFD700',
  Low: '#7CFC00',
  Info: '#4FC3F7',
};

function generatePdfReport(jsonReport) {
  ensureReportsDir();
  const filePath = path.join(REPORTS_DIR, `${jsonReport.auditId}.pdf`);
  const doc = new PDFDocument({ margin: 50, size: 'A4' });
  const stream = fs.createWriteStream(filePath);
  doc.pipe(stream);

  // --- Header ---
  doc
    .rect(0, 0, doc.page.width, 90)
    .fill('#0B0F1A');
  doc
    .fillColor('#00E5FF')
    .fontSize(22)
    .font('Helvetica-Bold')
    .text('CipherGate Audit Report', 50, 28);
  doc
    .fillColor('#9FB3C8')
    .fontSize(10)
    .font('Helvetica')
    .text('Authentication Security Assessment', 50, 58);

  doc.moveDown(4);
  doc.fillColor('#000000');

  // --- Meta info ---
  doc.fontSize(11).font('Helvetica-Bold').text('Website:', { continued: true }).font('Helvetica').text(` ${jsonReport.website}`);
  doc.font('Helvetica-Bold').text('Audit Date:', { continued: true }).font('Helvetica').text(` ${jsonReport.auditDate}`);
  doc.font('Helvetica-Bold').text('Audit ID:', { continued: true }).font('Helvetica').text(` ${jsonReport.auditId}`);
  doc.moveDown();

  // --- Score box ---
  const scoreColor = jsonReport.riskScore.color || '#000000';
  const boxTop = doc.y;
  const boxHeight = 70;
  doc.roundedRect(50, boxTop, 495, boxHeight, 6).fillAndStroke('#F5F7FA', '#E0E5EB');
  doc
    .fillColor(scoreColor)
    .fontSize(28)
    .font('Helvetica-Bold')
    .text(`${jsonReport.riskScore.value}/100`, 65, boxTop + 18, { lineBreak: false });
  doc
    .fillColor('#333333')
    .fontSize(12)
    .font('Helvetica-Bold')
    .text(`Rating: ${jsonReport.riskScore.rating}`, 200, boxTop + 16, { lineBreak: false });
  doc
    .fillColor('#555555')
    .fontSize(10)
    .font('Helvetica')
    .text(
      `${jsonReport.stats.passed} passed / ${jsonReport.stats.failed} failed of ${jsonReport.stats.totalChecks} checks`,
      200,
      boxTop + 38,
      { lineBreak: false }
    );

  doc.y = boxTop + boxHeight + 20;
  doc.x = 50;

  // --- Executive summary ---
  doc.fillColor('#000000').fontSize(14).font('Helvetica-Bold').text('Executive Summary');
  doc.moveDown(0.3);
  doc.fontSize(10).font('Helvetica').text(jsonReport.executiveSummary, { align: 'justify' });
  doc.moveDown();

  // --- Failed checks ---
  doc.fontSize(14).font('Helvetica-Bold').text('Failed Checks & Recommendations');
  doc.moveDown(0.3);

  if (jsonReport.failedChecks.length === 0) {
    doc.fontSize(10).font('Helvetica').fillColor('#2E7D32').text('No failed checks — excellent security posture.');
  } else {
    jsonReport.failedChecks.forEach((check, idx) => {
      if (doc.y > 700) doc.addPage();
      const color = SEVERITY_COLORS[check.severity] || '#333333';
      doc
        .fontSize(11)
        .font('Helvetica-Bold')
        .fillColor(color)
        .text(`${idx + 1}. [${check.severity}] ${check.name}`, { continued: false });
      doc.fillColor('#333333').fontSize(9.5).font('Helvetica').text(`Module: ${check.module}`);
      doc.text(`Issue: ${check.detail}`);
      doc.font('Helvetica-Bold').text('Mitigation: ', { continued: true }).font('Helvetica').text(check.recommendation);
      doc.moveDown(0.5);
    });
  }

  doc.moveDown();

  // --- Passed checks (compact) ---
  if (doc.y > 650) doc.addPage();
  doc.fillColor('#000000').fontSize(14).font('Helvetica-Bold').text('Passed Checks');
  doc.moveDown(0.3);
  doc.fontSize(9.5).font('Helvetica').fillColor('#2E7D32');
  jsonReport.passedChecks.forEach((check) => {
    if (doc.y > 760) doc.addPage();
    doc.text(`✔ ${check.name} (${check.module})`);
  });

  // --- Footer ---
  doc.fontSize(8).fillColor('#999999').text(
    `Generated by CipherGate (built by @mahesha) on ${new Date().toISOString()} — For authorized security testing only.`,
    50,
    doc.page.height - 40,
    { align: 'center' }
  );

  doc.end();

  return new Promise((resolve, reject) => {
    stream.on('finish', () => resolve(filePath));
    stream.on('error', reject);
  });
}

module.exports = { buildJsonReport, saveJsonReport, generatePdfReport, REPORTS_DIR };
