// services/mfaScanner.js
// Heuristically detects references to multi-factor authentication on the page.

const { SEVERITY, MFA_SIGNATURES } = require('../utils/constants');

function scanMfa(html) {
  const findings = [];
  const detected = MFA_SIGNATURES.filter((sig) => sig.pattern.test(html));

  findings.push({
    id: 'mfaHint',
    name: 'Multi-Factor Authentication (MFA) Indicators',
    passed: detected.length > 0,
    severity: SEVERITY.MEDIUM,
    detail:
      detected.length > 0
        ? `Possible MFA mechanisms referenced on page: ${detected.map((d) => d.name).join(', ')}. (Heuristic text-based detection — verify manually.)`
        : 'No text/markup referencing MFA, OTP, or 2FA was found on this page. This does not guarantee MFA is unavailable — it may be offered only after initial login.',
    recommendation:
      detected.length > 0
        ? 'Confirm MFA is enforceable (not merely optional) for privileged accounts, and supports phishing-resistant methods like passkeys/WebAuthn.'
        : 'Offer MFA (TOTP authenticator, WebAuthn/passkeys, or SMS as a fallback) to reduce credential-stuffing and phishing impact.',
  });

  return { module: 'MFA Scanner', findings, detected: detected.map((d) => d.name) };
}

module.exports = { scanMfa };
