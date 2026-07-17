import type { CheckFn, Finding } from '../types.js';

interface ParsedCookie {
  name: string;
  raw: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string | null;
}

/**
 * Parses a raw Set-Cookie header string into a structured object.
 */
function parseCookie(raw: string): ParsedCookie {
  const parts = raw.split(';').map((p) => p.trim());
  const nameValue = parts[0] ?? '';
  const name = nameValue.split('=')[0]?.trim() ?? 'unknown';

  const attrs = parts.slice(1).map((p) => p.toLowerCase());

  const secure = attrs.includes('secure');
  const httpOnly = attrs.includes('httponly');

  const sameSiteAttr = attrs.find((a) => a.startsWith('samesite='));
  const sameSite = sameSiteAttr ? sameSiteAttr.split('=')[1]?.trim() ?? null : null;

  return { name, raw, secure, httpOnly, sameSite };
}

/**
 * Checks Set-Cookie headers for missing security flags.
 *
 * Rules per cookie:
 *  - Missing Secure flag        → high
 *  - Missing HttpOnly flag      → medium
 *  - Missing SameSite attribute → medium
 *  - SameSite=None without Secure → high (spec violation + security risk)
 */
export const checkCookies: CheckFn = async (_url, response) => {
  const findings: Finding[] = [];
  const h = response.headers;

  // Set-Cookie can appear multiple times; axios joins them with ', '
  // but they can also come as a single comma-separated string
  const rawSetCookie = h['set-cookie'];
  if (!rawSetCookie) return findings;

  // Split carefully: cookie values can contain commas, but date fields like
  // "Expires=Mon, 01 Jan 2025 00:00:00 GMT" also have commas.
  // We split on commas NOT followed by a space + word + =
  // A pragmatic heuristic: split on ", " only where next token looks like a new cookie name
  const cookieStrings = rawSetCookie
    .split(/,\s*(?=[^;,]+=)/)
    .filter(Boolean);

  for (const raw of cookieStrings) {
    const cookie = parseCookie(raw);

    // ── High: missing Secure flag ────────────────────────────────────────────
    if (!cookie.secure) {
      findings.push({
        id: `cookie-missing-secure-${cookie.name}`,
        title: `Cookie '${cookie.name}' is missing the Secure flag`,
        severity: 'high',
        description: `The cookie '${cookie.name}' is set without the Secure flag, meaning it can be transmitted over unencrypted HTTP connections, making it vulnerable to interception (man-in-the-middle attacks).`,
        recommendation: `Add the Secure flag to the '${cookie.name}' cookie: Set-Cookie: ${cookie.name}=...; Secure; ...`,
        evidence: raw.slice(0, 200),
      });
    }

    // ── High: SameSite=None without Secure ───────────────────────────────────
    if (cookie.sameSite === 'none' && !cookie.secure) {
      findings.push({
        id: `cookie-samesite-none-no-secure-${cookie.name}`,
        title: `Cookie '${cookie.name}' has SameSite=None without Secure`,
        severity: 'high',
        description: `The cookie '${cookie.name}' uses SameSite=None, which allows cross-site requests, but is missing the Secure flag. Browsers require the Secure flag when SameSite=None, and without it the cookie may be rejected or transmitted insecurely.`,
        recommendation: `Add the Secure flag: Set-Cookie: ${cookie.name}=...; SameSite=None; Secure`,
        evidence: raw.slice(0, 200),
      });
    }

    // ── Medium: missing HttpOnly flag ────────────────────────────────────────
    if (!cookie.httpOnly) {
      findings.push({
        id: `cookie-missing-httponly-${cookie.name}`,
        title: `Cookie '${cookie.name}' is missing the HttpOnly flag`,
        severity: 'medium',
        description: `The cookie '${cookie.name}' is accessible via JavaScript (document.cookie). If an XSS vulnerability exists, attackers can steal this cookie.`,
        recommendation: `Add the HttpOnly flag: Set-Cookie: ${cookie.name}=...; HttpOnly; ...`,
        evidence: raw.slice(0, 200),
      });
    }

    // ── Medium: missing SameSite attribute ───────────────────────────────────
    if (cookie.sameSite === null) {
      findings.push({
        id: `cookie-missing-samesite-${cookie.name}`,
        title: `Cookie '${cookie.name}' is missing the SameSite attribute`,
        severity: 'medium',
        description: `The cookie '${cookie.name}' has no SameSite attribute. Without it, the browser may send the cookie on cross-site requests, enabling CSRF attacks.`,
        recommendation: `Add SameSite=Strict or SameSite=Lax: Set-Cookie: ${cookie.name}=...; SameSite=Lax; ...`,
        evidence: raw.slice(0, 200),
      });
    }
  }

  return findings;
};
