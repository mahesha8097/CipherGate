// services/scoreCalculator.js
// Combines findings from every scanner module into a single 0-100 security score.

const { CHECK_WEIGHTS, SCORE_BANDS } = require('../utils/constants');

function getScoreBand(score) {
  return SCORE_BANDS.find((band) => score >= band.min) || SCORE_BANDS[SCORE_BANDS.length - 1];
}

/**
 * @param {Array<{module: string, findings: Array}>} moduleResults
 */
function calculateScore(moduleResults) {
  let score = 100;
  const allFindings = [];

  moduleResults.forEach((mod) => {
    mod.findings.forEach((f) => {
      allFindings.push({ ...f, module: mod.module });
      if (f.informational) return; // informational findings never affect score
      if (!f.passed) {
        const weight = CHECK_WEIGHTS[f.id] ?? 3; // default small deduction for unweighted checks
        score -= weight;
      }
    });
  });

  score = Math.max(0, Math.min(100, Math.round(score)));

  const passedChecks = allFindings.filter((f) => f.passed && !f.informational);
  const failedChecks = allFindings.filter((f) => !f.passed && !f.informational);
  const infoChecks = allFindings.filter((f) => f.informational);

  const band = getScoreBand(score);

  return {
    score,
    label: band.label,
    color: band.color,
    totalChecks: passedChecks.length + failedChecks.length,
    passedCount: passedChecks.length,
    failedCount: failedChecks.length,
    passedChecks,
    failedChecks,
    infoChecks,
    allFindings,
  };
}

module.exports = { calculateScore, getScoreBand };
