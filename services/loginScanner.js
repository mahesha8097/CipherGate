// services/loginScanner.js
// Parses HTML with Cheerio to locate and evaluate the login form.

const cheerio = require('cheerio');
const { SEVERITY } = require('../utils/constants');

function findLoginForm($) {
  let loginForm = null;

  $('form').each((_, form) => {
    const $form = $(form);
    const hasPasswordField = $form.find('input[type="password"]').length > 0;
    if (hasPasswordField && !loginForm) {
      loginForm = $form;
    }
  });

  return loginForm;
}

function scanLoginForm(html) {
  const $ = cheerio.load(html);
  const findings = [];
  const loginForm = findLoginForm($);

  if (!loginForm) {
    findings.push({
      id: 'loginFormDetected',
      name: 'Login Form Detection',
      passed: true,
      severity: SEVERITY.INFO,
      detail:
        'No login form with a password field was found on this page. It may be rendered dynamically via JavaScript, or located at a different URL (e.g. /login).',
      recommendation: 'If the site uses a JS-rendered login form, re-run the audit against the direct login URL.',
      informational: true,
    });
    return { module: 'Login Scanner', findings, formFound: false };
  }

  findings.push({
    id: 'loginFormDetected',
    name: 'Login Form Detection',
    passed: true,
    severity: SEVERITY.INFO,
    detail: 'A login form with a password field was found on the page.',
    recommendation: 'None.',
    informational: true,
  });

  const passwordField = loginForm.find('input[type="password"]').first();
  const autocomplete = (passwordField.attr('autocomplete') || '').toLowerCase();
  const autocompleteDisabled = autocomplete === 'off' || autocomplete === 'new-password' ? false : autocomplete === '' ? null : null;

  // autocomplete="off" on password fields is now discouraged (breaks password managers);
  // best practice is autocomplete="current-password".
  const usesCurrentPassword = autocomplete === 'current-password';
  findings.push({
    id: 'autocompleteOnPassword',
    name: 'Password Manager Compatibility (autocomplete)',
    passed: autocomplete !== 'off',
    severity: SEVERITY.LOW,
    detail:
      autocomplete === 'off'
        ? 'The password field explicitly disables autocomplete, which discourages the use of password managers.'
        : usesCurrentPassword
        ? 'The password field correctly uses autocomplete="current-password", supporting password managers.'
        : 'The password field does not explicitly disable autocomplete.',
    recommendation:
      'Use autocomplete="current-password" (login) or "new-password" (signup) rather than disabling autocomplete, so users can rely on password managers.',
  });

  const formAction = loginForm.attr('action') || '';
  const formMethod = (loginForm.attr('method') || 'GET').toUpperCase();
  findings.push({
    id: 'formMethod',
    name: 'Form Submission Method',
    passed: formMethod === 'POST',
    severity: SEVERITY.MEDIUM,
    detail: `Login form submits via ${formMethod}${formAction ? ` to "${formAction}"` : ''}.`,
    recommendation:
      formMethod === 'POST'
        ? 'None.'
        : 'Login forms must submit via POST — GET submissions expose credentials in URLs, browser history, and server logs.',
  });

  const rememberMe = loginForm.find('input[type="checkbox"]').filter((_, el) => {
    const nameOrId = (`${$(el).attr('name') || ''} ${$(el).attr('id') || ''}`).toLowerCase();
    return /remember/i.test(nameOrId);
  });
  findings.push({
    id: 'rememberMe',
    name: '"Remember Me" Option',
    passed: true,
    severity: SEVERITY.INFO,
    detail:
      rememberMe.length > 0
        ? 'A "Remember Me" option was detected on the login form.'
        : 'No "Remember Me" option was detected.',
    recommendation:
      rememberMe.length > 0
        ? 'Ensure "Remember Me" tokens are long-lived but revocable, and stored as HttpOnly + Secure cookies.'
        : 'None.',
    informational: true,
  });

  const usernameField = loginForm
    .find('input[type="text"], input[type="email"], input:not([type])')
    .first();
  const usernameType = usernameField.attr('type') || 'text';
  findings.push({
    id: 'usernameFieldType',
    name: 'Username/Email Field Type',
    passed: true,
    severity: SEVERITY.INFO,
    detail: `Identifier field uses type="${usernameType}".`,
    recommendation: 'None.',
    informational: true,
  });

  return {
    module: 'Login Scanner',
    findings,
    formFound: true,
    formAction,
    formMethod,
  };
}

module.exports = { scanLoginForm, findLoginForm };
