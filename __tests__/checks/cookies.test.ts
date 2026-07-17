import { describe, it, expect } from 'vitest';
import { checkCookies } from '../../src/scanner/checks/cookies.js';
import type { HttpResponse } from '../../src/scanner/types.js';

function makeResponse(setCookie?: string): HttpResponse {
  return {
    status: 200,
    headers: setCookie ? { 'set-cookie': setCookie } : {},
    body: '',
    url: 'https://example.com',
    redirectChain: [],
  };
}

describe('checkCookies', () => {
  it('returns no findings when no Set-Cookie header is present', async () => {
    const findings = await checkCookies('https://example.com', makeResponse());
    expect(findings).toHaveLength(0);
  });

  it('flags missing Secure flag as high', async () => {
    const findings = await checkCookies(
      'https://example.com',
      makeResponse('session=abc123; HttpOnly; SameSite=Lax'),
    );
    const f = findings.find((f) => f.id.startsWith('cookie-missing-secure'));
    expect(f).toBeDefined();
    expect(f?.severity).toBe('high');
  });

  it('flags missing HttpOnly flag as medium', async () => {
    const findings = await checkCookies(
      'https://example.com',
      makeResponse('session=abc123; Secure; SameSite=Lax'),
    );
    const f = findings.find((f) => f.id.startsWith('cookie-missing-httponly'));
    expect(f).toBeDefined();
    expect(f?.severity).toBe('medium');
  });

  it('flags missing SameSite attribute as medium', async () => {
    const findings = await checkCookies(
      'https://example.com',
      makeResponse('session=abc123; Secure; HttpOnly'),
    );
    const f = findings.find((f) => f.id.startsWith('cookie-missing-samesite'));
    expect(f).toBeDefined();
    expect(f?.severity).toBe('medium');
  });

  it('flags SameSite=None without Secure as high', async () => {
    const findings = await checkCookies(
      'https://example.com',
      makeResponse('cross-site=value; HttpOnly; SameSite=None'),
    );
    const f = findings.find((f) => f.id.startsWith('cookie-samesite-none-no-secure'));
    expect(f).toBeDefined();
    expect(f?.severity).toBe('high');
  });

  it('does not flag SameSite=None with Secure', async () => {
    const findings = await checkCookies(
      'https://example.com',
      makeResponse('cross-site=value; Secure; HttpOnly; SameSite=None'),
    );
    expect(findings.find((f) => f.id.startsWith('cookie-samesite-none-no-secure'))).toBeUndefined();
  });

  it('returns no security findings for a fully hardened cookie', async () => {
    const findings = await checkCookies(
      'https://example.com',
      makeResponse('session=abc123; Secure; HttpOnly; SameSite=Strict'),
    );
    const securityFindings = findings.filter((f) => f.severity !== 'info');
    expect(securityFindings).toHaveLength(0);
  });

  it('uses the cookie name in the finding id', async () => {
    const findings = await checkCookies(
      'https://example.com',
      makeResponse('my_token=xyz; HttpOnly; SameSite=Lax'),
    );
    const secureFinding = findings.find((f) => f.id.includes('my_token'));
    expect(secureFinding).toBeDefined();
  });
});
