// services/tlsScanner.js
// Checks HTTPS enforcement, TLS certificate details, and mixed-content risk.

const tls = require('tls');
const { URL } = require('url');
const { SEVERITY } = require('../utils/constants');

/** Opens a raw TLS socket to inspect the certificate & negotiated protocol. */
function inspectCertificate(hostname, port = 443, timeoutMs = 8000) {
  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host: hostname,
        port,
        servername: hostname,
        timeout: timeoutMs,
        rejectUnauthorized: false, // we want to inspect, not reject, invalid certs
      },
      () => {
        const cert = socket.getPeerCertificate();
        const protocol = socket.getProtocol();
        const authorized = socket.authorized;
        socket.end();
        resolve({
          success: true,
          protocol,
          authorized,
          validFrom: cert.valid_from,
          validTo: cert.valid_to,
          issuer: cert.issuer ? cert.issuer.O || cert.issuer.CN : 'Unknown',
          subject: cert.subject ? cert.subject.CN : hostname,
        });
      }
    );

    socket.on('error', (err) => {
      resolve({ success: false, error: err.message });
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve({ success: false, error: 'TLS connection timed out' });
    });
  });
}

/** Scans the raw HTML for http:// resource references on an https page (mixed content). */
function detectMixedContent(html, pageUrl) {
  if (!pageUrl.startsWith('https://')) return { hasMixedContent: false, examples: [] };

  const matches = [...html.matchAll(/(?:src|href)=["']http:\/\/[^"']+["']/gi)].map((m) => m[0]);
  const unique = [...new Set(matches)].slice(0, 5);

  return { hasMixedContent: unique.length > 0, examples: unique };
}

async function scanTls(targetUrl, html) {
  const parsed = new URL(targetUrl);
  const isHttps = parsed.protocol === 'https:';
  const findings = [];

  findings.push({
    id: 'https',
    name: 'HTTPS Enforcement',
    passed: isHttps,
    severity: SEVERITY.CRITICAL,
    detail: isHttps
      ? 'The site is served over HTTPS.'
      : 'The site is served over plain HTTP. Credentials submitted on this page can be intercepted in transit.',
    recommendation: 'Serve the entire site (especially login/auth pages) exclusively over HTTPS with HSTS enabled.',
  });

  let certInfo = null;
  if (isHttps) {
    certInfo = await inspectCertificate(parsed.hostname, parsed.port || 443);

    if (certInfo.success) {
      const now = new Date();
      const expiry = new Date(certInfo.validTo);
      const daysToExpiry = Math.round((expiry - now) / (1000 * 60 * 60 * 24));
      const oldProtocol = ['TLSv1', 'TLSv1.1'].includes(certInfo.protocol);

      findings.push({
        id: 'tlsProtocol',
        name: 'TLS Protocol Version',
        passed: !oldProtocol,
        severity: SEVERITY.HIGH,
        detail: `Negotiated protocol: ${certInfo.protocol || 'Unknown'}${
          oldProtocol ? ' (outdated and deprecated)' : ''
        }`,
        recommendation: 'Disable TLS 1.0/1.1 on the server; support only TLS 1.2 and TLS 1.3.',
      });

      findings.push({
        id: 'certValidity',
        name: 'Certificate Validity',
        passed: certInfo.authorized && daysToExpiry > 0,
        severity: SEVERITY.CRITICAL,
        detail: certInfo.authorized
          ? `Certificate is trusted, issued by ${certInfo.issuer}, expires in ${daysToExpiry} day(s) (${certInfo.validTo}).`
          : `Certificate is NOT trusted by standard CA validation (issuer: ${certInfo.issuer}).`,
        recommendation: certInfo.authorized
          ? 'Ensure the certificate is renewed well before its expiry date.'
          : 'Install a certificate from a publicly trusted Certificate Authority.',
      });
    } else {
      findings.push({
        id: 'certValidity',
        name: 'Certificate Validity',
        passed: false,
        severity: SEVERITY.MEDIUM,
        detail: `Unable to inspect TLS certificate: ${certInfo.error}`,
        recommendation: 'Verify the TLS handshake works correctly from external networks.',
        informational: true,
      });
    }
  }

  if (html) {
    const mixedContent = detectMixedContent(html, targetUrl);
    findings.push({
      id: 'mixedContent',
      name: 'Mixed Content',
      passed: !mixedContent.hasMixedContent,
      severity: SEVERITY.MEDIUM,
      detail: mixedContent.hasMixedContent
        ? `Found ${mixedContent.examples.length} insecure (http://) resource reference(s), e.g. ${mixedContent.examples[0]}`
        : 'No insecure http:// resource references detected on an HTTPS page.',
      recommendation: 'Load all page resources (scripts, images, stylesheets) over HTTPS to avoid mixed-content warnings and MITM risk.',
    });
  }

  return {
    module: 'TLS Scanner',
    findings,
    certificate: certInfo,
  };
}

module.exports = { scanTls, inspectCertificate, detectMixedContent };
