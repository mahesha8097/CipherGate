// utils/validator.js
// Validates and normalizes user-supplied target URLs before any network call is made.

const { URL } = require('url');

/**
 * Blocks obviously dangerous / internal targets to reduce SSRF risk
 * (localhost, private IP ranges, link-local, metadata endpoints).
 */
const BLOCKED_HOSTNAME_PATTERNS = [
  /^localhost$/i,
  /^127\./,
  /^0\.0\.0\.0$/,
  /^10\./,
  /^192\.168\./,
  /^169\.254\./, // link-local / cloud metadata
  /^172\.(1[6-9]|2\d|3[0-1])\./,
  /^\[::1\]$/,
  /^::1$/,
];

function isBlockedHostname(hostname) {
  return BLOCKED_HOSTNAME_PATTERNS.some((re) => re.test(hostname));
}

/**
 * Normalizes and validates a URL string.
 * @param {string} rawUrl
 * @returns {{ valid: boolean, url?: string, error?: string }}
 */
function validateTargetUrl(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string') {
    return { valid: false, error: 'A website URL is required.' };
  }

  let candidate = rawUrl.trim();
  if (!/^https?:\/\//i.test(candidate)) {
    candidate = `https://${candidate}`;
  }

  let parsed;
  try {
    parsed = new URL(candidate);
  } catch (err) {
    return { valid: false, error: 'The provided URL is not valid.' };
  }

  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return { valid: false, error: 'Only http:// and https:// URLs are supported.' };
  }

  if (isBlockedHostname(parsed.hostname)) {
    return { valid: false, error: 'Scanning internal/private/loopback addresses is not permitted.' };
  }

  if (!parsed.hostname.includes('.') && parsed.hostname !== 'localhost') {
    return { valid: false, error: 'The hostname does not look like a valid domain.' };
  }

  return { valid: true, url: parsed.toString() };
}

module.exports = { validateTargetUrl, isBlockedHostname };
