// services/cookieScanner.js
// Analyzes Set-Cookie headers for Secure, HttpOnly, and SameSite attributes.

const { SEVERITY } = require('../utils/constants');
const { parseSetCookies } = require('../utils/helpers');

function scanCookies(setCookieHeader, isHttps) {
  const cookies = parseSetCookies(setCookieHeader);
  const findings = [];

  if (cookies.length === 0) {
    findings.push({
      id: 'noCookies',
      name: 'Cookie Presence',
      passed: true,
      severity: SEVERITY.INFO,
      detail: 'No cookies were set on the initial response (session cookies may be set post-login).',
      recommendation: 'None — re-run the audit against an authenticated session if session cookies need inspection.',
      informational: true,
    });
    return { module: 'Cookie Scanner', findings, cookies: [] };
  }

  const insecureCookies = cookies.filter((c) => isHttps && !c.secure);
  const nonHttpOnlyCookies = cookies.filter((c) => !c.httpOnly);
  const noSameSiteCookies = cookies.filter((c) => !c.sameSite);
  const looseSameSiteCookies = cookies.filter(
    (c) => c.sameSite && c.sameSite.toLowerCase() === 'none'
  );

  findings.push({
    id: 'secureCookies',
    name: 'Secure Attribute',
    passed: insecureCookies.length === 0,
    severity: SEVERITY.HIGH,
    detail:
      insecureCookies.length === 0
        ? `All ${cookies.length} cookie(s) set the Secure attribute (or site is served over HTTP).`
        : `${insecureCookies.length} of ${cookies.length} cookie(s) missing the Secure attribute: ${insecureCookies
            .map((c) => c.name)
            .join(', ')}`,
    recommendation:
      'Mark all authentication/session cookies with the Secure attribute so they are only sent over HTTPS.',
  });

  findings.push({
    id: 'httpOnlyCookies',
    name: 'HttpOnly Attribute',
    passed: nonHttpOnlyCookies.length === 0,
    severity: SEVERITY.HIGH,
    detail:
      nonHttpOnlyCookies.length === 0
        ? `All ${cookies.length} cookie(s) set the HttpOnly attribute.`
        : `${nonHttpOnlyCookies.length} of ${cookies.length} cookie(s) missing HttpOnly: ${nonHttpOnlyCookies
            .map((c) => c.name)
            .join(', ')}`,
    recommendation:
      'Mark session/auth cookies HttpOnly so they cannot be read or exfiltrated via JavaScript (mitigates XSS-based session theft).',
  });

  findings.push({
    id: 'sameSiteCookies',
    name: 'SameSite Attribute',
    passed: noSameSiteCookies.length === 0 && looseSameSiteCookies.length === 0,
    severity: SEVERITY.MEDIUM,
    detail:
      noSameSiteCookies.length === 0
        ? `All cookies define a SameSite policy.${
            looseSameSiteCookies.length
              ? ` Note: ${looseSameSiteCookies.length} use SameSite=None.`
              : ''
          }`
        : `${noSameSiteCookies.length} cookie(s) do not specify SameSite: ${noSameSiteCookies
            .map((c) => c.name)
            .join(', ')}`,
    recommendation:
      'Set "SameSite=Strict" or "SameSite=Lax" on session cookies to reduce CSRF exposure. Reserve SameSite=None (+Secure) for cross-site use cases only.',
  });

  return {
    module: 'Cookie Scanner',
    findings,
    cookies: cookies.map((c) => ({
      name: c.name,
      secure: c.secure,
      httpOnly: c.httpOnly,
      sameSite: c.sameSite || 'Not set',
    })),
  };
}

module.exports = { scanCookies };
