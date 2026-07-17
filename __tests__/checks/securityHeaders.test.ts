import { describe, it, expect } from 'vitest';
import { checkSecurityHeaders } from '../../src/scanner/checks/securityHeaders.js';
import type { HttpResponse } from '../../src/scanner/types.js';

function makeResponse(headers: Record<string, string> = {}): HttpResponse {
  return {
    status: 200,
    headers,
    body: '',
    url: 'https://example.com',
    redirectChain: [],
  };
}

describe('checkSecurityHeaders', () => {
  it('flags missing CSP as critical', async () => {
    const findings = await checkSecurityHeaders('https://example.com', makeResponse({}));
    const csp = findings.find((f) => f.id === 'missing-csp');
    expect(csp).toBeDefined();
    expect(csp?.severity).toBe('critical');
  });

  it('flags weak CSP (unsafe-inline) as high', async () => {
    const findings = await checkSecurityHeaders(
      'https://example.com',
      makeResponse({ 'content-security-policy': "default-src 'self'; script-src 'unsafe-inline'" }),
    );
    expect(findings.find((f) => f.id === 'weak-csp')).toBeDefined();
  });

  it('does not flag CSP when valid policy is present', async () => {
    const findings = await checkSecurityHeaders(
      'https://example.com',
      makeResponse({ 'content-security-policy': "default-src 'self'; object-src 'none'" }),
    );
    expect(findings.find((f) => f.id === 'missing-csp')).toBeUndefined();
    expect(findings.find((f) => f.id === 'weak-csp')).toBeUndefined();
  });

  it('flags missing HSTS as high', async () => {
    const findings = await checkSecurityHeaders('https://example.com', makeResponse({}));
    expect(findings.find((f) => f.id === 'missing-hsts')?.severity).toBe('high');
  });

  it('flags HSTS with short max-age as medium', async () => {
    const findings = await checkSecurityHeaders(
      'https://example.com',
      makeResponse({ 'strict-transport-security': 'max-age=86400' }),
    );
    expect(findings.find((f) => f.id === 'weak-hsts-max-age')?.severity).toBe('medium');
  });

  it('does not flag HSTS with adequate max-age', async () => {
    const findings = await checkSecurityHeaders(
      'https://example.com',
      makeResponse({ 'strict-transport-security': 'max-age=31536000; includeSubDomains' }),
    );
    expect(findings.find((f) => f.id === 'missing-hsts')).toBeUndefined();
    expect(findings.find((f) => f.id === 'weak-hsts-max-age')).toBeUndefined();
  });

  it('flags missing X-Frame-Options as medium', async () => {
    const findings = await checkSecurityHeaders('https://example.com', makeResponse({}));
    expect(findings.find((f) => f.id === 'missing-x-frame-options')?.severity).toBe('medium');
  });

  it('flags missing X-Content-Type-Options as medium', async () => {
    const findings = await checkSecurityHeaders('https://example.com', makeResponse({}));
    expect(findings.find((f) => f.id === 'missing-x-content-type-options')?.severity).toBe('medium');
  });

  it('flags invalid X-Content-Type-Options value', async () => {
    const findings = await checkSecurityHeaders(
      'https://example.com',
      makeResponse({ 'x-content-type-options': 'sniff' }),
    );
    expect(findings.find((f) => f.id === 'invalid-x-content-type-options')).toBeDefined();
  });

  it('does not flag X-Content-Type-Options when set to nosniff', async () => {
    const findings = await checkSecurityHeaders(
      'https://example.com',
      makeResponse({ 'x-content-type-options': 'nosniff' }),
    );
    expect(findings.find((f) => f.id?.startsWith('missing-x-content-type') || f.id?.startsWith('invalid-x-content'))).toBeUndefined();
  });

  it('flags Server header disclosure as info', async () => {
    const findings = await checkSecurityHeaders(
      'https://example.com',
      makeResponse({ server: 'nginx/1.18.0' }),
    );
    expect(findings.find((f) => f.id === 'server-header-disclosure')?.severity).toBe('info');
  });

  it('flags X-Powered-By disclosure as info', async () => {
    const findings = await checkSecurityHeaders(
      'https://example.com',
      makeResponse({ 'x-powered-by': 'Express' }),
    );
    expect(findings.find((f) => f.id === 'x-powered-by-disclosure')?.severity).toBe('info');
  });

  it('returns no findings for a fully hardened response', async () => {
    const secureHeaders: Record<string, string> = {
      'content-security-policy': "default-src 'self'; object-src 'none'",
      'strict-transport-security': 'max-age=31536000; includeSubDomains; preload',
      'x-frame-options': 'DENY',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'strict-origin-when-cross-origin',
      'permissions-policy': 'camera=(), microphone=(), geolocation=()',
    };
    const findings = await checkSecurityHeaders('https://example.com', makeResponse(secureHeaders));
    // Should only possibly have server-disclosure if server header present, but we didn't set it
    const importantFindings = findings.filter((f) => f.severity !== 'info');
    expect(importantFindings).toHaveLength(0);
  });
});
