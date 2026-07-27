// services/jwtScanner.js
// Looks for JWT-shaped tokens in cookies/HTML and inspects their (unverified) header + payload.
// NOTE: We only ever decode — never verify with a secret — since we don't have the server's key.

const { SEVERITY } = require('../utils/constants');

const JWT_REGEX = /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g;

function base64UrlDecode(str) {
  try {
    const padded = str.padEnd(str.length + ((4 - (str.length % 4)) % 4), '=');
    const base64 = padded.replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(Buffer.from(base64, 'base64').toString('utf8'));
  } catch {
    return null;
  }
}

function findJwtsInText(text) {
  if (!text) return [];
  const matches = text.match(JWT_REGEX) || [];
  return [...new Set(matches)];
}

function scanJwt(html, headers = {}) {
  const findings = [];
  const cookieHeader = headers['set-cookie'];
  const cookieText = Array.isArray(cookieHeader) ? cookieHeader.join(' ') : cookieHeader || '';

  const tokens = [...findJwtsInText(html), ...findJwtsInText(cookieText)];

  if (tokens.length === 0) {
    findings.push({
      id: 'jwtDetection',
      name: 'JWT Detection',
      passed: true,
      severity: SEVERITY.INFO,
      detail: 'No JWT-formatted tokens were observed in the page HTML or cookies at this stage (may only appear post-login).',
      recommendation: 'None — re-run against an authenticated session/API response if JWT usage needs verification.',
      informational: true,
    });
    return { module: 'JWT Scanner', findings, tokens: [] };
  }

  const analyzed = tokens.slice(0, 3).map((token) => {
    const [headerPart, payloadPart] = token.split('.');
    const header = base64UrlDecode(headerPart);
    const payload = base64UrlDecode(payloadPart);
    return { token: `${token.slice(0, 16)}...`, header, payload };
  });

  findings.push({
    id: 'jwtDetection',
    name: 'JWT Detection',
    passed: true,
    severity: SEVERITY.INFO,
    detail: `${tokens.length} JWT-formatted token(s) detected.`,
    recommendation: 'None.',
    informational: true,
  });

  analyzed.forEach((item, idx) => {
    const alg = item.header && item.header.alg;
    const weakAlg = alg && (alg.toLowerCase() === 'none' || alg.toUpperCase() === 'HS256');
    findings.push({
      id: `jwtAlg_${idx}`,
      name: `JWT #${idx + 1} — Signing Algorithm`,
      passed: alg && alg.toLowerCase() !== 'none',
      severity: SEVERITY.CRITICAL,
      detail: alg
        ? `Algorithm: ${alg}${
            alg.toLowerCase() === 'none'
              ? ' — CRITICAL: "none" algorithm allows unsigned/forged tokens.'
              : alg.toUpperCase() === 'HS256'
              ? ' (symmetric — ensure the shared secret is strong and never exposed client-side).'
              : ''
          }`
        : 'Unable to decode JWT header.',
      recommendation:
        alg && alg.toLowerCase() === 'none'
          ? 'Never accept tokens signed with "alg: none". Enforce an explicit allow-list of algorithms server-side (e.g. RS256).'
          : 'Prefer asymmetric algorithms (RS256/ES256) for tokens verified by multiple services; rotate signing keys periodically.',
    });

    if (item.payload) {
      const exp = item.payload.exp;
      const hasExpiry = Boolean(exp);
      const expiryDate = hasExpiry ? new Date(exp * 1000) : null;
      findings.push({
        id: `jwtExp_${idx}`,
        name: `JWT #${idx + 1} — Expiry Claim`,
        passed: hasExpiry,
        severity: SEVERITY.HIGH,
        detail: hasExpiry
          ? `Token expires at ${expiryDate.toISOString()}.`
          : 'Token has no "exp" (expiry) claim — it may never expire.',
        recommendation: hasExpiry
          ? 'Use short-lived access tokens (minutes-hours) paired with a refresh token flow.'
          : 'Always set an "exp" claim on issued JWTs to limit the blast radius of a leaked token.',
      });
    }
  });

  return { module: 'JWT Scanner', findings, tokens: analyzed };
}

module.exports = { scanJwt };
