// services/captchaScanner.js
// Detects the presence of common CAPTCHA / bot-mitigation providers.

const { SEVERITY, CAPTCHA_SIGNATURES } = require('../utils/constants');

function scanCaptcha(html) {
  const findings = [];
  const detected = CAPTCHA_SIGNATURES.filter((sig) => sig.pattern.test(html));

  findings.push({
    id: 'captchaPresent',
    name: 'CAPTCHA / Bot Protection',
    passed: detected.length > 0,
    severity: SEVERITY.MEDIUM,
    detail:
      detected.length > 0
        ? `Detected: ${detected.map((d) => d.name).join(', ')}`
        : 'No CAPTCHA or bot-mitigation provider was detected on this page. The login form may be susceptible to automated credential stuffing / brute force.',
    recommendation:
      detected.length > 0
        ? 'Ensure CAPTCHA is enforced server-side (not just rendered client-side) and triggers after repeated failed attempts.'
        : 'Add a CAPTCHA (reCAPTCHA, hCaptcha, or Turnstile) and/or rate limiting on the login endpoint to deter automated attacks.',
  });

  return { module: 'CAPTCHA Scanner', findings, detected: detected.map((d) => d.name) };
}

module.exports = { scanCaptcha };
