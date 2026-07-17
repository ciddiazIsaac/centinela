import type { CheckFn, Finding } from '../types.js';

/**
 * Checks for the presence and basic correctness of HTTP security headers.
 *
 * Headers evaluated:
 *  - Content-Security-Policy      → critical if missing
 *  - Strict-Transport-Security    → high if missing (or insecure max-age)
 *  - X-Frame-Options              → medium if missing
 *  - X-Content-Type-Options       → medium if missing
 *  - Referrer-Policy              → low if missing
 *  - Permissions-Policy           → low if missing
 */
export const checkSecurityHeaders: CheckFn = async (_url, response) => {
  const findings: Finding[] = [];
  const h = response.headers;

  // ── Content-Security-Policy ────────────────────────────────────────────────
  if (!h['content-security-policy']) {
    findings.push({
      id: 'missing-csp',
      title: 'Missing Content-Security-Policy header',
      severity: 'critical',
      description:
        'No Content-Security-Policy (CSP) header was found. CSP prevents cross-site scripting (XSS), clickjacking, and other code injection attacks by specifying which dynamic resources are allowed to load.',
      recommendation:
        "Add a Content-Security-Policy header. Start with a strict policy such as: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self';",
    });
  } else {
    const csp = h['content-security-policy'];
    // Warn about dangerous directives
    if (csp.includes("'unsafe-inline'") || csp.includes("'unsafe-eval'")) {
      findings.push({
        id: 'weak-csp',
        title: "Content-Security-Policy uses unsafe directives",
        severity: 'high',
        description:
          "The Content-Security-Policy header includes 'unsafe-inline' or 'unsafe-eval', which significantly weakens XSS protection.",
        recommendation:
          "Remove 'unsafe-inline' and 'unsafe-eval' from your CSP. Use nonces or hashes for inline scripts instead.",
        evidence: csp,
      });
    }
  }

  // ── Strict-Transport-Security ──────────────────────────────────────────────
  if (!h['strict-transport-security']) {
    findings.push({
      id: 'missing-hsts',
      title: 'Missing Strict-Transport-Security header',
      severity: 'high',
      description:
        'The Strict-Transport-Security (HSTS) header is absent. Without HSTS, browsers may connect over insecure HTTP before being redirected, leaving users vulnerable to downgrade attacks.',
      recommendation:
        'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
    });
  } else {
    const hsts = h['strict-transport-security'];
    const maxAgeMatch = hsts.match(/max-age=(\d+)/i);
    if (maxAgeMatch) {
      const maxAge = parseInt(maxAgeMatch[1], 10);
      if (maxAge < 15768000) {
        // less than ~6 months
        findings.push({
          id: 'weak-hsts-max-age',
          title: 'HSTS max-age is too short',
          severity: 'medium',
          description: `The Strict-Transport-Security max-age is only ${maxAge} seconds (${Math.floor(maxAge / 86400)} days). It should be at least 6 months (15768000 seconds).`,
          recommendation:
            'Set max-age to at least 31536000 (1 year): Strict-Transport-Security: max-age=31536000; includeSubDomains',
          evidence: hsts,
        });
      }
    }
  }

  // ── X-Frame-Options ────────────────────────────────────────────────────────
  if (!h['x-frame-options']) {
    findings.push({
      id: 'missing-x-frame-options',
      title: 'Missing X-Frame-Options header',
      severity: 'medium',
      description:
        'The X-Frame-Options header is missing. Without it, the page can be embedded in iframes on other domains, enabling clickjacking attacks.',
      recommendation:
        'Add: X-Frame-Options: DENY  (or SAMEORIGIN if you need same-origin framing)',
    });
  }

  // ── X-Content-Type-Options ────────────────────────────────────────────────
  if (!h['x-content-type-options']) {
    findings.push({
      id: 'missing-x-content-type-options',
      title: 'Missing X-Content-Type-Options header',
      severity: 'medium',
      description:
        'The X-Content-Type-Options header is absent. Browsers may MIME-sniff responses, allowing attackers to trick the browser into interpreting files as a different content type.',
      recommendation: 'Add: X-Content-Type-Options: nosniff',
    });
  } else if (h['x-content-type-options'].toLowerCase() !== 'nosniff') {
    findings.push({
      id: 'invalid-x-content-type-options',
      title: 'X-Content-Type-Options has an invalid value',
      severity: 'medium',
      description: `X-Content-Type-Options should be set to 'nosniff'. Current value: '${h['x-content-type-options']}'.`,
      recommendation: 'Set: X-Content-Type-Options: nosniff',
      evidence: h['x-content-type-options'],
    });
  }

  // ── Referrer-Policy ────────────────────────────────────────────────────────
  if (!h['referrer-policy']) {
    findings.push({
      id: 'missing-referrer-policy',
      title: 'Missing Referrer-Policy header',
      severity: 'low',
      description:
        'No Referrer-Policy header found. The browser may send the full URL as the Referer header to third parties, potentially leaking sensitive URL parameters.',
      recommendation:
        'Add: Referrer-Policy: strict-origin-when-cross-origin  (or no-referrer for maximum privacy)',
    });
  }

  // ── Permissions-Policy ────────────────────────────────────────────────────
  if (!h['permissions-policy']) {
    findings.push({
      id: 'missing-permissions-policy',
      title: 'Missing Permissions-Policy header',
      severity: 'low',
      description:
        'No Permissions-Policy header was found. This header lets you control which browser features (camera, microphone, geolocation, etc.) can be used by your page and embedded content.',
      recommendation:
        'Add a Permissions-Policy header restricting unused features. Example: Permissions-Policy: camera=(), microphone=(), geolocation=()',
    });
  }

  // ── Info: server banner disclosure ────────────────────────────────────────
  if (h['server'] && h['server'].length > 0) {
    findings.push({
      id: 'server-header-disclosure',
      title: 'Server header discloses software version',
      severity: 'info',
      description:
        'The Server header reveals the web server software and potentially its version, giving attackers information to identify targeted exploits.',
      recommendation:
        'Configure your web server to suppress or genericise the Server header.',
      evidence: h['server'],
    });
  }

  if (h['x-powered-by']) {
    findings.push({
      id: 'x-powered-by-disclosure',
      title: 'X-Powered-By header discloses technology stack',
      severity: 'info',
      description:
        'The X-Powered-By header reveals the backend technology (e.g. Express, PHP). This aids fingerprinting.',
      recommendation:
        'Remove the X-Powered-By header. In Express: app.disable("x-powered-by") or use helmet().',
      evidence: h['x-powered-by'],
    });
  }

  return findings;
};
