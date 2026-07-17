import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { HttpResponse } from '../src/scanner/types.js';

// Mock httpClient so engine tests don't make real HTTP requests
vi.mock('../src/utils/httpClient.js', () => ({
  fetchUrl: vi.fn(),
}));

import { fetchUrl } from '../src/utils/httpClient.js';
import { scan } from '../src/scanner/engine.js';

const mockFetchUrl = vi.mocked(fetchUrl);

/** A response with no security headers at all — worst case */
const INSECURE_RESPONSE: HttpResponse = {
  status: 200,
  headers: {
    server: 'nginx/1.18.0',
    'x-powered-by': 'Express',
    'access-control-allow-origin': '*',
    'access-control-allow-credentials': 'true',
    'set-cookie': 'session=abc; Path=/',
  },
  body: '<html></html>',
  url: 'https://victim.example.com',
  redirectChain: [],
};

/** A response with all security headers properly set */
const SECURE_RESPONSE: HttpResponse = {
  status: 200,
  headers: {
    'content-security-policy': "default-src 'self'; object-src 'none'",
    'strict-transport-security': 'max-age=31536000; includeSubDomains',
    'x-frame-options': 'DENY',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'strict-origin-when-cross-origin',
    'permissions-policy': 'camera=(), microphone=()',
  },
  body: '<html></html>',
  url: 'https://secure.example.com',
  redirectChain: [],
};

describe('engine.scan() — integration', () => {
  beforeEach(() => {
    // Default: all path probes return 404
    mockFetchUrl.mockResolvedValue({ ...INSECURE_RESPONSE, status: 404 });
  });

  it('returns a ScanReport with expected shape', async () => {
    mockFetchUrl.mockResolvedValueOnce(INSECURE_RESPONSE);

    const report = await scan('https://victim.example.com');

    expect(report).toMatchObject({
      id: expect.any(String),
      url: 'https://victim.example.com',
      scannedAt: expect.any(String),
      duration: expect.any(Number),
      score: expect.any(Number),
      findings: expect.any(Array),
      summary: {
        critical: expect.any(Number),
        high: expect.any(Number),
        medium: expect.any(Number),
        low: expect.any(Number),
        info: expect.any(Number),
      },
    });
  });

  it('detects multiple issues on an insecure response', async () => {
    mockFetchUrl.mockResolvedValueOnce(INSECURE_RESPONSE);

    const report = await scan('https://victim.example.com');

    // Should detect: missing CSP, missing HSTS, missing X-Frame-Options,
    // missing X-Content-Type-Options, CORS wildcard+credentials (critical),
    // server banner, X-Powered-By, missing Referrer-Policy, missing Permissions-Policy,
    // cookie without Secure/HttpOnly/SameSite
    expect(report.findings.length).toBeGreaterThan(5);
    expect(report.summary.critical).toBeGreaterThan(0);
  });

  it('score is lower for insecure response than for a secured one', async () => {
    // First call: insecure (main request)
    mockFetchUrl.mockResolvedValueOnce(INSECURE_RESPONSE);
    const insecureReport = await scan('https://victim.example.com');

    // Second call: secure (main request) + path probes all 404
    mockFetchUrl.mockResolvedValueOnce(SECURE_RESPONSE);
    const secureReport = await scan('https://secure.example.com');

    expect(secureReport.score).toBeGreaterThan(insecureReport.score);
  });

  it('score is capped at 0 (never negative)', async () => {
    mockFetchUrl.mockResolvedValueOnce(INSECURE_RESPONSE);
    const report = await scan('https://victim.example.com');
    expect(report.score).toBeGreaterThanOrEqual(0);
  });

  it('score is at most 100', async () => {
    mockFetchUrl.mockResolvedValueOnce(SECURE_RESPONSE);
    const report = await scan('https://secure.example.com');
    expect(report.score).toBeLessThanOrEqual(100);
  });

  it('findings are sorted by severity (critical first)', async () => {
    mockFetchUrl.mockResolvedValueOnce(INSECURE_RESPONSE);
    const report = await scan('https://victim.example.com');

    const severityOrder: Record<string, number> = {
      critical: 0, high: 1, medium: 2, low: 3, info: 4,
    };

    for (let i = 0; i < report.findings.length - 1; i++) {
      const current = severityOrder[report.findings[i].severity] ?? 99;
      const next = severityOrder[report.findings[i + 1].severity] ?? 99;
      expect(current).toBeLessThanOrEqual(next);
    }
  });

  it('summary counts match actual findings array', async () => {
    mockFetchUrl.mockResolvedValueOnce(INSECURE_RESPONSE);
    const report = await scan('https://victim.example.com');

    const counted = report.findings.reduce(
      (acc, f) => { acc[f.severity] = (acc[f.severity] ?? 0) + 1; return acc; },
      {} as Record<string, number>,
    );

    expect(report.summary.critical).toBe(counted['critical'] ?? 0);
    expect(report.summary.high).toBe(counted['high'] ?? 0);
    expect(report.summary.medium).toBe(counted['medium'] ?? 0);
    expect(report.summary.low).toBe(counted['low'] ?? 0);
    expect(report.summary.info).toBe(counted['info'] ?? 0);
  });

  it('each scan report has a unique id (uuid)', async () => {
    mockFetchUrl.mockResolvedValue(INSECURE_RESPONSE);
    const r1 = await scan('https://a.example.com');
    const r2 = await scan('https://b.example.com');
    expect(r1.id).not.toBe(r2.id);
    expect(r1.id).toMatch(/^[0-9a-f-]{36}$/);
  });

  it('throws when httpClient throws (network failure)', async () => {
    mockFetchUrl.mockRejectedValueOnce(new Error('ECONNREFUSED'));
    await expect(scan('https://down.example.com')).rejects.toThrow('ECONNREFUSED');
  });
});
