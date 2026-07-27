// public/js/main.js
// Handles the scan form on the landing page: submits the target URL to
// POST /audit, shows progress, then redirects to the report page.

document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('scan-form');
  const input = document.getElementById('url-input');
  const submitBtn = document.getElementById('scan-btn');
  const loadingWrap = document.getElementById('loading-wrap');
  const loadingStep = document.getElementById('loading-step');
  const progressFill = document.getElementById('progress-fill');
  const errorBanner = document.getElementById('error-banner');

  if (!form) return;

  const STEPS = [
    'Resolving target host...',
    'Fetching login page over HTTPS...',
    'Inspecting security headers...',
    'Analyzing cookies (Secure / HttpOnly / SameSite)...',
    'Checking TLS certificate & protocol...',
    'Scanning login form for CSRF protection...',
    'Detecting CAPTCHA & MFA indicators...',
    'Inspecting JWT tokens (if present)...',
    'Calculating security score...',
    'Generating audit report...',
  ];

  let stepInterval;

  function startProgress() {
    let i = 0;
    let pct = 0;
    loadingStep.textContent = STEPS[0];
    progressFill.style.width = '4%';
    stepInterval = setInterval(() => {
      i = Math.min(i + 1, STEPS.length - 1);
      pct = Math.min(pct + 10, 92);
      loadingStep.textContent = STEPS[i];
      progressFill.style.width = `${pct}%`;
    }, 550);
  }

  function stopProgress() {
    clearInterval(stepInterval);
    progressFill.style.width = '100%';
  }

  function showError(message) {
    errorBanner.textContent = message;
    errorBanner.classList.add('active');
  }

  function hideError() {
    errorBanner.classList.remove('active');
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideError();

    const url = input.value.trim();
    if (!url) {
      showError('Please enter a website URL to audit.');
      return;
    }

    submitBtn.disabled = true;
    loadingWrap.classList.add('active');
    startProgress();

    try {
      const res = await fetch('/audit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });

      const data = await res.json();

      if (!res.ok || !data.success) {
        throw new Error((data.error && data.error.message) || 'The audit could not be completed.');
      }

      stopProgress();
      sessionStorage.setItem('latestAuditReport', JSON.stringify(data.data));
      window.location.href = `/report?auditId=${encodeURIComponent(data.data.auditId)}`;
    } catch (err) {
      clearInterval(stepInterval);
      loadingWrap.classList.remove('active');
      submitBtn.disabled = false;
      showError(err.message || 'Something went wrong while running the audit.');
    }
  });
});
