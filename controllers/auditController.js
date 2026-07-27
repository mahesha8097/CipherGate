// controllers/auditController.js

const axios = require('axios');
const { validateTargetUrl } = require('../utils/validator');
const { generateAuditId, asyncHandler } = require('../utils/helpers');
const { AppError } = require('../middleware/errorHandler');
const { DEFAULT_TIMEOUT_MS, DEFAULT_USER_AGENT } = require('../utils/constants');

const { scanHeaders } = require('../services/headerScanner');
const { scanCookies } = require('../services/cookieScanner');
const { scanTls } = require('../services/tlsScanner');
const { scanLoginForm } = require('../services/loginScanner');
const { scanCsrf } = require('../services/csrfScanner');
const { scanJwt } = require('../services/jwtScanner');
const { scanCaptcha } = require('../services/captchaScanner');
const { scanMfa } = require('../services/mfaScanner');
const { calculateScore } = require('../services/scoreCalculator');
const { buildJsonReport, saveJsonReport, generatePdfReport } = require('../services/reportGenerator');

// In-memory store of recent audits (for the "Audit History" dashboard feature).
// In production this would be a database; kept simple here for portfolio purposes.
const auditHistory = [];
const MAX_HISTORY = 25;

/** Fetches the target page, following redirects, with a hard timeout. */
async function fetchTarget(targetUrl) {
  const response = await axios.get(targetUrl, {
    timeout: Number(process.env.REQUEST_TIMEOUT_MS) || DEFAULT_TIMEOUT_MS,
    maxRedirects: Number(process.env.MAX_REDIRECTS) || 5,
    validateStatus: () => true, // we want to inspect even 4xx/5xx responses
    headers: { 'User-Agent': process.env.USER_AGENT || DEFAULT_USER_AGENT },
  });
  return response;
}

const runAudit = asyncHandler(async (req, res) => {
  const { url } = req.body;
  const validation = validateTargetUrl(url);

  if (!validation.valid) {
    throw new AppError(validation.error, 400);
  }

  const targetUrl = validation.url;
  const startedAt = new Date();
  const auditId = generateAuditId();

  let response;
  try {
    response = await fetchTarget(targetUrl);
  } catch (err) {
    throw new AppError(
      `Unable to reach ${targetUrl}: ${err.code || err.message}. The site may be offline, blocking automated requests, or unreachable from this network.`,
      502
    );
  }

  const headers = response.headers || {};
  const html = typeof response.data === 'string' ? response.data : '';
  const isHttps = targetUrl.startsWith('https://');

  // Run all scanner modules
  const [tlsResult] = await Promise.all([scanTls(targetUrl, html)]);
  const headerResult = scanHeaders(headers);
  const cookieResult = scanCookies(headers['set-cookie'], isHttps);
  const loginResult = scanLoginForm(html);
  const csrfResult = scanCsrf(html, headers);
  const jwtResult = scanJwt(html, headers);
  const captchaResult = scanCaptcha(html);
  const mfaResult = scanMfa(html);

  const moduleResults = [
    tlsResult,
    headerResult,
    cookieResult,
    loginResult,
    csrfResult,
    jwtResult,
    captchaResult,
    mfaResult,
  ];

  const scoreResult = calculateScore(moduleResults);

  const auditData = { auditId, targetUrl, scoreResult, moduleResults, startedAt };
  const jsonReport = buildJsonReport(auditData);

  // Persist for report download endpoints + history dashboard
  saveJsonReport(jsonReport);
  auditHistory.unshift({
    auditId,
    website: targetUrl,
    score: scoreResult.score,
    rating: scoreResult.label,
    date: jsonReport.auditDate,
  });
  if (auditHistory.length > MAX_HISTORY) auditHistory.pop();

  res.status(200).json({
    success: true,
    data: jsonReport,
  });
});

const getHistory = (req, res) => {
  res.status(200).json({ success: true, data: auditHistory });
};

module.exports = { runAudit, getHistory, auditHistory };
