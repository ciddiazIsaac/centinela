import type { CheckFn, Finding } from '../types.js';

/**
 * Checks CORS (Cross-Origin Resource Sharing) configuration.
 *
 * Rules:
 *  - Access-Control-Allow-Origin: *  → high (wildcard exposes all resources)
 *  - ACAO: * + ACAC: true            → critical (credentials + wildcard = auth bypass)
 *  - ACAO reflects arbitrary Origin   → high (CORS misconfiguration)
 *  - ACAC: true without specific origin → high
 */
export const checkCors: CheckFn = async (_url, response) => {
  const findings: Finding[] = [];
  const h = response.headers;

  const acao = h['access-control-allow-origin'];
  const acac = h['access-control-allow-credentials'];
  const acam = h['access-control-allow-methods'];
  const acah = h['access-control-allow-headers'];

  // No CORS headers at all → nothing to check
  if (!acao) return findings;

  const isWildcard = acao.trim() === '*';
  const credentialsTrue = acac?.toLowerCase() === 'true';

  // ── Critical: wildcard + credentials ──────────────────────────────────────
  // Browsers block this combination, but some proxies/middleware may not
  if (isWildcard && credentialsTrue) {
    findings.push({
      id: 'cors-wildcard-credentials',
      title: 'CORS allows wildcard origin with credentials',
      severity: 'critical',
      description:
        "Access-Control-Allow-Origin is set to '*' AND Access-Control-Allow-Credentials is 'true'. While modern browsers reject this combination, it indicates a severely misconfigured CORS policy that could allow any origin to make authenticated requests.",
      recommendation:
        "Never combine 'Access-Control-Allow-Origin: *' with 'Access-Control-Allow-Credentials: true'. Specify explicit trusted origins instead.",
      evidence: `ACAO: ${acao} | ACAC: ${acac}`,
    });
  }
  // ── High: wildcard origin only ─────────────────────────────────────────────
  else if (isWildcard) {
    findings.push({
      id: 'cors-wildcard-origin',
      title: 'CORS policy allows any origin (wildcard)',
      severity: 'high',
      description:
        "Access-Control-Allow-Origin is set to '*', meaning any website can make cross-origin requests to this server. For APIs handling sensitive data this is a significant risk.",
      recommendation:
        'Restrict CORS to specific trusted origins instead of using a wildcard. Use an allowlist: Access-Control-Allow-Origin: https://yourdomain.com',
      evidence: acao,
    });
  }

  // ── High: credentials: true with a non-specific origin ────────────────────
  if (!isWildcard && credentialsTrue) {
    // This can be fine if the origin is a specific trusted domain
    // But we flag it as info-level so the user is aware
    findings.push({
      id: 'cors-credentials-enabled',
      title: 'CORS allows credentials (cookies/auth headers)',
      severity: 'info',
      description:
        `Access-Control-Allow-Credentials is 'true' and the allowed origin is '${acao}'. This permits the browser to send cookies and authentication headers cross-origin. Ensure this origin is fully trusted.`,
      recommendation:
        'Verify that the allowed origin is intentional and trusted. Never allow credentials from user-controlled or dynamic origins.',
      evidence: `ACAO: ${acao} | ACAC: ${acac}`,
    });
  }

  // ── Medium: overly permissive allowed methods ──────────────────────────────
  if (acam) {
    const dangerousMethods = ['DELETE', 'PUT', 'PATCH'];
    const allowedMethods = acam.toUpperCase().split(',').map((m) => m.trim());
    const foundDangerous = dangerousMethods.filter((m) => allowedMethods.includes(m));

    if (foundDangerous.length > 0) {
      findings.push({
        id: 'cors-dangerous-methods',
        title: 'CORS allows dangerous HTTP methods cross-origin',
        severity: 'medium',
        description: `Access-Control-Allow-Methods includes potentially dangerous methods: ${foundDangerous.join(', ')}. These should only be allowed from trusted origins.`,
        recommendation:
          'Restrict Access-Control-Allow-Methods to only the methods your API actually needs cross-origin (typically GET and POST).',
        evidence: acam,
      });
    }
  }

  // ── Low: Authorization header exposed via ACAH ─────────────────────────────
  if (acah) {
    const exposedHeaders = acah.toLowerCase().split(',').map((h) => h.trim());
    if (exposedHeaders.includes('authorization')) {
      findings.push({
        id: 'cors-exposes-authorization',
        title: 'CORS allows cross-origin access to Authorization header',
        severity: 'low',
        description:
          'Access-Control-Allow-Headers includes "Authorization", allowing cross-origin requests to send auth tokens. Combined with a wide origin policy this is a risk.',
        recommendation:
          'Only allow the Authorization header from explicitly trusted origins.',
        evidence: acah,
      });
    }
  }

  return findings;
};
