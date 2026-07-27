// utils/constants.js
// Central place for scoring weights, severity levels, and known signatures.

module.exports = {
  SEVERITY: {
    CRITICAL: 'Critical',
    HIGH: 'High',
    MEDIUM: 'Medium',
    LOW: 'Low',
    INFO: 'Info',
  },

  // Weight (points deducted from 100) if a check fails.
  // These are tuned so the total possible deduction roughly spans 0-100.
  CHECK_WEIGHTS: {
    https: 15,
    hsts: 8,
    csp: 8,
    xFrameOptions: 5,
    xContentTypeOptions: 4,
    referrerPolicy: 3,
    permissionsPolicy: 3,
    corsWildcard: 6,
    secureCookies: 8,
    httpOnlyCookies: 8,
    sameSiteCookies: 6,
    csrfProtection: 8,
    captchaPresent: 4,
    mfaHint: 5,
    autocompleteOnPassword: 3,
    jwtWeakAlg: 6,
    mixedContent: 8,
  },

  SCORE_BANDS: [
    { min: 90, label: 'Excellent', color: '#00ff9d' },
    { min: 75, label: 'Good', color: '#7CFC00' },
    { min: 55, label: 'Moderate', color: '#FFD700' },
    { min: 35, label: 'Weak', color: '#FF8C00' },
    { min: 0, label: 'Critical', color: '#FF3B3B' },
  ],

  CAPTCHA_SIGNATURES: [
    { name: 'Google reCAPTCHA', pattern: /recaptcha|grecaptcha/i },
    { name: 'Cloudflare Turnstile', pattern: /turnstile|challenges\.cloudflare\.com/i },
    { name: 'hCaptcha', pattern: /hcaptcha/i },
    { name: 'FunCaptcha / Arkose Labs', pattern: /arkoselabs|funcaptcha/i },
  ],

  MFA_SIGNATURES: [
    { name: 'One-Time Password (OTP)', pattern: /\botp\b|one[-\s]?time\s?password/i },
    { name: 'Authenticator App', pattern: /authenticator\s?app|google authenticator|authy/i },
    { name: 'SMS Verification', pattern: /sms\s?(code|verification)|text message code/i },
    { name: 'Two-Factor Authentication', pattern: /two[-\s]?factor|2fa|multi[-\s]?factor|mfa/i },
    { name: 'Security Questions', pattern: /security question/i },
    { name: 'Passkey / WebAuthn', pattern: /passkey|webauthn|fido2/i },
  ],

  CSRF_SIGNATURES: [
    /csrf[-_]?token/i,
    /authenticity_token/i,
    /__requestverificationtoken/i,
    /_csrf/i,
    /xsrf[-_]?token/i,
  ],

  SECURITY_HEADERS: [
    'strict-transport-security',
    'content-security-policy',
    'x-frame-options',
    'x-content-type-options',
    'referrer-policy',
    'permissions-policy',
    'x-xss-protection',
  ],

  DEFAULT_TIMEOUT_MS: 15000,
  DEFAULT_USER_AGENT:
    'Mozilla/5.0 (compatible; CipherGate/1.0; +https://github.com/mahesha8097/ciphergate)',
};
