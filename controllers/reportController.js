// controllers/reportController.js

const fs = require('fs');
const path = require('path');
const { AppError } = require('../middleware/errorHandler');
const { asyncHandler } = require('../utils/helpers');
const { REPORTS_DIR, generatePdfReport } = require('../services/reportGenerator');

/** GET /report/json/:auditId */
const getJsonReport = asyncHandler(async (req, res) => {
  const { auditId } = req.params;
  const filePath = path.join(REPORTS_DIR, `${sanitizeId(auditId)}.json`);

  if (!fs.existsSync(filePath)) {
    throw new AppError('Report not found. It may have expired or the audit ID is incorrect.', 404);
  }

  res.setHeader('Content-Disposition', `attachment; filename="${auditId}.json"`);
  res.setHeader('Content-Type', 'application/json');
  fs.createReadStream(filePath).pipe(res);
});

/** GET /report/pdf/:auditId */
const getPdfReport = asyncHandler(async (req, res) => {
  const { auditId } = req.params;
  const jsonPath = path.join(REPORTS_DIR, `${sanitizeId(auditId)}.json`);
  const pdfPath = path.join(REPORTS_DIR, `${sanitizeId(auditId)}.pdf`);

  if (!fs.existsSync(jsonPath)) {
    throw new AppError('Report not found. It may have expired or the audit ID is incorrect.', 404);
  }

  // Generate the PDF on-demand (cached after first generation) from the stored JSON report.
  if (!fs.existsSync(pdfPath)) {
    const jsonReport = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
    await generatePdfReport(jsonReport);
  }

  res.setHeader('Content-Disposition', `attachment; filename="${auditId}.pdf"`);
  res.setHeader('Content-Type', 'application/pdf');
  fs.createReadStream(pdfPath).pipe(res);
});

/** Prevents path traversal via the auditId param. */
function sanitizeId(id) {
  return String(id).replace(/[^a-zA-Z0-9_]/g, '');
}

module.exports = { getJsonReport, getPdfReport };
