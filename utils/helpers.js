// utils/helpers.js

const { v4: uuidv4 } = require('uuid');

/** Generates a unique audit ID. */
function generateAuditId() {
  return `audit_${Date.now()}_${uuidv4().slice(0, 8)}`;
}

/** Formats a Date to a readable string like "26 Jul 2026, 14:32 IST". */
function formatDate(date = new Date()) {
  return date.toLocaleString('en-IN', {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    timeZone: 'Asia/Kolkata',
    timeZoneName: 'short',
  });
}

/** Safely parses Set-Cookie header(s) into an array of cookie objects. */
function parseSetCookies(setCookieHeader) {
  if (!setCookieHeader) return [];
  const rawCookies = Array.isArray(setCookieHeader) ? setCookieHeader : [setCookieHeader];

  return rawCookies.map((raw) => {
    const parts = raw.split(';').map((p) => p.trim());
    const [nameValue, ...attrs] = parts;
    const [name, value] = nameValue.split('=');

    const cookie = {
      name: name ? name.trim() : 'unknown',
      value: value ? '***redacted***' : '',
      secure: false,
      httpOnly: false,
      sameSite: null,
      raw,
    };

    attrs.forEach((attr) => {
      const lower = attr.toLowerCase();
      if (lower === 'secure') cookie.secure = true;
      if (lower === 'httponly') cookie.httpOnly = true;
      if (lower.startsWith('samesite')) {
        cookie.sameSite = attr.split('=')[1] || 'Lax';
      }
    });

    return cookie;
  });
}

/** Truncates long strings for display purposes. */
function truncate(str, max = 120) {
  if (!str) return '';
  return str.length > max ? `${str.slice(0, max)}...` : str;
}

/** Wraps an async function so errors are forwarded to Express's error handler. */
function asyncHandler(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}

module.exports = {
  generateAuditId,
  formatDate,
  parseSetCookies,
  truncate,
  asyncHandler,
};
