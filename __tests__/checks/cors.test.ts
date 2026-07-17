import { describe, it, expect } from 'vitest';
import { checkCors } from '../../src/scanner/checks/cors.js';
import type { HttpResponse } from '../../src/scanner/types.js';

function makeResponse(headers: Record<string, string> = {}): HttpResponse {
  return {
    status: 200,
    headers,
    body: '',
    url: 'https://api.example.com',
    redirectChain: [],
  };
}

describe('checkCors', () => {
  it('returns no findings when no CORS headers are present', async () => {
    const findings = await checkCors('https://api.example.com', makeResponse({}));
    expect(findings).toHaveLength(0);
  });

  it('flags ACAO wildcard as high', async () => {
    const findings = await checkCors(
      'https://api.example.com',
      makeResponse({ 'access-control-allow-origin': '*' }),
    );
    const f = findings.find((f) => f.id === 'cors-wildcard-origin');
    expect(f).toBeDefined();
    expect(f?.severity).toBe('high');
  });

  it('flags ACAO wildcard + ACAC true as critical', async () => {
    const findings = await checkCors(
      'https://api.example.com',
      makeResponse({
        'access-control-allow-origin': '*',
        'access-control-allow-credentials': 'true',
      }),
    );
    const f = findings.find((f) => f.id === 'cors-wildcard-credentials');
    expect(f).toBeDefined();
    expect(f?.severity).toBe('critical');
  });

  it('does not flag wildcard-credentials when credentials is false', async () => {
    const findings = await checkCors(
      'https://api.example.com',
      makeResponse({
        'access-control-allow-origin': '*',
        'access-control-allow-credentials': 'false',
      }),
    );
    expect(findings.find((f) => f.id === 'cors-wildcard-credentials')).toBeUndefined();
    // But should still flag wildcard-origin
    expect(findings.find((f) => f.id === 'cors-wildcard-origin')).toBeDefined();
  });

  it('flags credentials: true with specific origin as info', async () => {
    const findings = await checkCors(
      'https://api.example.com',
      makeResponse({
        'access-control-allow-origin': 'https://trusted.example.com',
        'access-control-allow-credentials': 'true',
      }),
    );
    const f = findings.find((f) => f.id === 'cors-credentials-enabled');
    expect(f).toBeDefined();
    expect(f?.severity).toBe('info');
  });

  it('flags dangerous ACAM methods (DELETE, PUT, PATCH) as medium', async () => {
    const findings = await checkCors(
      'https://api.example.com',
      makeResponse({
        'access-control-allow-origin': '*',
        'access-control-allow-methods': 'GET, POST, DELETE, PUT',
      }),
    );
    const f = findings.find((f) => f.id === 'cors-dangerous-methods');
    expect(f).toBeDefined();
    expect(f?.severity).toBe('medium');
  });

  it('does not flag safe ACAM methods', async () => {
    const findings = await checkCors(
      'https://api.example.com',
      makeResponse({
        'access-control-allow-origin': '*',
        'access-control-allow-methods': 'GET, POST, OPTIONS',
      }),
    );
    expect(findings.find((f) => f.id === 'cors-dangerous-methods')).toBeUndefined();
  });

  it('flags ACAH exposing Authorization header as low', async () => {
    const findings = await checkCors(
      'https://api.example.com',
      makeResponse({
        'access-control-allow-origin': '*',
        'access-control-allow-headers': 'Content-Type, Authorization',
      }),
    );
    const f = findings.find((f) => f.id === 'cors-exposes-authorization');
    expect(f).toBeDefined();
    expect(f?.severity).toBe('low');
  });
});
