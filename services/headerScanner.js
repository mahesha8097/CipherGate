// services/headerScanner.js
// Inspects HTTP response headers for standard security header hygiene.

const { SEVERITY } = require('../utils/constants');

/**
 * @param {object} headers - lowercase-keyed response headers object (axios style)
 * @returns {object} structured findings
 */
function scanHeaders(headers = {}) {
  const findings = [];

  // --- HSTS ---
  const hsts = headers['strict-transport-security'];
  findings.push({
    id: 'hsts',
    name: 'HTTP Strict Transport Security (HSTS)',
    passed: Boolean(hsts),
    severity: SEVERITY.HIGH,
    detail: hsts
      ? `HSTS header present: ${hsts}`
      : 'No Strict-Transport-Security header found. Browsers may allow downgraded HTTP connections.',
    recommendation:
      'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload" to enforce HTTPS-only connections.',
  });

  // --- CSP ---
  const csp = headers['content-security-policy'];
  findings.push({
    id: 'csp',
    name: 'Content Security Policy (CSP)',
    passed: Boolean(csp),
    severity: SEVERITY.HIGH,
    detail: csp
      ? `CSP header present (${csp.length} chars).`
      : 'No Content-Security-Policy header found. This increases exposure to XSS-based session/credential theft.',
    recommendation:
      'Define a strict CSP (e.g. default-src \'self\') to reduce the impact of injected scripts on login pages.',
  });

  // --- X-Frame-Options ---
  const xfo = headers['x-frame-options'];
  findings.push({
    id: 'xFrameOptions',
    name: 'X-Frame-Options (Clickjacking Protection)',
    passed: Boolean(xfo),
    severity: SEVERITY.MEDIUM,
    detail: xfo ? `X-Frame-Options: ${xfo}` : 'No X-Frame-Options header found.',
    recommendation:
      'Set "X-Frame-Options: DENY" or use CSP\'s frame-ancestors directive to prevent clickjacking on the login form.',
  });

  // --- X-Content-Type-Options ---
  const xcto = headers['x-content-type-options'];
  findings.push({
    id: 'xContentTypeOptions',
    name: 'X-Content-Type-Options',
    passed: xcto === 'nosniff',
    severity: SEVERITY.LOW,
    detail: xcto ? `X-Content-Type-Options: ${xcto}` : 'No X-Content-Type-Options header found.',
    recommendation: 'Set "X-Content-Type-Options: nosniff" to prevent MIME-sniffing attacks.',
  });

  // --- Referrer-Policy ---
  const referrer = headers['referrer-policy'];
  findings.push({
    id: 'referrerPolicy',
    name: 'Referrer Policy',
    passed: Boolean(referrer),
    severity: SEVERITY.LOW,
    detail: referrer ? `Referrer-Policy: ${referrer}` : 'No Referrer-Policy header found.',
    recommendation:
      'Set "Referrer-Policy: strict-origin-when-cross-origin" to avoid leaking full URLs (which may contain tokens) to third parties.',
  });

  // --- Permissions-Policy ---
  const permissionsPolicy = headers['permissions-policy'];
  findings.push({
    id: 'permissionsPolicy',
    name: 'Permissions Policy',
    passed: Boolean(permissionsPolicy),
    severity: SEVERITY.LOW,
    detail: permissionsPolicy
      ? `Permissions-Policy: ${permissionsPolicy}`
      : 'No Permissions-Policy header found.',
    recommendation:
      'Define a Permissions-Policy to restrict access to sensitive browser APIs (camera, geolocation, etc.) on the auth pages.',
  });

  // --- CORS ---
  const acao = headers['access-control-allow-origin'];
  const corsWildcardWithCreds =
    acao === '*' && headers['access-control-allow-credentials'] === 'true';
  findings.push({
    id: 'corsWildcard',
    name: 'CORS Configuration',
    passed: !corsWildcardWithCreds,
    severity: SEVERITY.HIGH,
    detail: acao
      ? `Access-Control-Allow-Origin: ${acao}${
          corsWildcardWithCreds ? ' (combined with credentials: true — unsafe)' : ''
        }`
      : 'No Access-Control-Allow-Origin header found (CORS not exposed on this endpoint).',
    recommendation:
      'Never combine a wildcard "*" origin with Access-Control-Allow-Credentials: true. Use an explicit allow-list of trusted origins.',
  });

  // --- X-XSS-Protection (legacy, informational only) ---
  const xxss = headers['x-xss-protection'];
  findings.push({
    id: 'xXssProtection',
    name: 'X-XSS-Protection (legacy)',
    passed: true, // informational, not scored
    severity: SEVERITY.INFO,
    detail: xxss
      ? `X-XSS-Protection: ${xxss} (deprecated header, superseded by CSP)`
      : 'X-XSS-Protection not set (expected — this header is deprecated; rely on CSP instead).',
    recommendation: 'No action required; modern browsers rely on Content-Security-Policy instead.',
    informational: true,
  });

  // --- Server / X-Powered-By disclosure ---
  const serverHeader = headers['server'];
  const poweredBy = headers['x-powered-by'];
  if (serverHeader || poweredBy) {
    findings.push({
      id: 'techDisclosure',
      name: 'Server Technology Disclosure',
      passed: false,
      severity: SEVERITY.LOW,
      detail: `Server response discloses: ${[serverHeader, poweredBy].filter(Boolean).join(', ')}`,
      recommendation: 'Suppress or generalize "Server" / "X-Powered-By" headers to reduce fingerprinting.',
      informational: true,
    });
  }

  return {
    module: 'Header Scanner',
    findings,
  };
}

module.exports = { scanHeaders };
