// services/csrfScanner.js
// Looks for anti-CSRF token indicators in forms, meta tags, and headers.

const cheerio = require('cheerio');
const { SEVERITY, CSRF_SIGNATURES } = require('../utils/constants');

function scanCsrf(html, headers = {}) {
  const $ = cheerio.load(html);
  const findings = [];
  let tokenFound = false;
  let source = null;

  // Hidden inputs
  $('input[type="hidden"]').each((_, el) => {
    const name = ($(el).attr('name') || '').toLowerCase();
    if (CSRF_SIGNATURES.some((re) => re.test(name))) {
      tokenFound = true;
      source = `hidden input: ${name}`;
    }
  });

  // Meta tags (common in SPA frameworks, e.g. Rails/Laravel)
  if (!tokenFound) {
    $('meta').each((_, el) => {
      const name = ($(el).attr('name') || '').toLowerCase();
      if (CSRF_SIGNATURES.some((re) => re.test(name))) {
        tokenFound = true;
        source = `meta tag: ${name}`;
      }
    });
  }

  // Double-submit cookie pattern
  const cookieHeader = headers['set-cookie'];
  if (!tokenFound && cookieHeader) {
    const cookies = Array.isArray(cookieHeader) ? cookieHeader.join('; ') : cookieHeader;
    if (CSRF_SIGNATURES.some((re) => re.test(cookies))) {
      tokenFound = true;
      source = 'double-submit CSRF cookie';
    }
  }

  // SameSite cookies act as a partial, modern CSRF mitigation even without a token
  const hasSameSiteStrictOrLax =
    cookieHeader &&
    /samesite=(strict|lax)/i.test(Array.isArray(cookieHeader) ? cookieHeader.join(';') : cookieHeader);

  findings.push({
    id: 'csrfProtection',
    name: 'CSRF Token Protection',
    passed: tokenFound || Boolean(hasSameSiteStrictOrLax),
    severity: SEVERITY.HIGH,
    detail: tokenFound
      ? `Anti-CSRF token detected (${source}).`
      : hasSameSiteStrictOrLax
      ? 'No explicit CSRF token found, but SameSite cookie attributes provide partial CSRF mitigation.'
      : 'No anti-CSRF token (hidden field, meta tag, or double-submit cookie) or SameSite cookie protection was detected.',
    recommendation: tokenFound
      ? 'Ensure the CSRF token is unique per session/request and validated server-side on every state-changing request.'
      : 'Implement synchronizer CSRF tokens on all state-changing forms, or at minimum set SameSite=Strict/Lax on session cookies.',
  });

  return { module: 'CSRF Scanner', findings, tokenFound, source };
}

module.exports = { scanCsrf };
