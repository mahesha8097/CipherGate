// routes/report.js

const express = require('express');
const { getJsonReport, getPdfReport } = require('../controllers/reportController');

const router = express.Router();

// GET /report/json/:auditId -> download the raw JSON report
router.get('/json/:auditId', getJsonReport);

// GET /report/pdf/:auditId -> download the generated PDF report
router.get('/pdf/:auditId', getPdfReport);

module.exports = router;
