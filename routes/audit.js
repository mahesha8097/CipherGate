// routes/audit.js

const express = require('express');
const rateLimit = require('express-rate-limit');
const { runAudit, getHistory } = require('../controllers/auditController');

const router = express.Router();

// A tighter rate limit specifically on the (expensive) audit endpoint.
const auditLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 10,
  message: { success: false, error: { message: 'Too many audit requests. Please wait a few minutes and try again.' } },
  standardHeaders: true,
  legacyHeaders: false,
});

// POST /audit  -> run a full authentication security audit on a target URL
router.post('/', auditLimiter, runAudit);

// GET /audit/history -> recent audits (for the dashboard)
router.get('/history', getHistory);

module.exports = router;
