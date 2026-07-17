import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { HttpResponse } from '../../src/scanner/types.js';

// Mock httpClient before importing the check
vi.mock('../../src/utils/httpClient.js', () => ({
  fetchUrl: vi.fn(),
}));

import { fetchUrl } from '../../src/utils/httpClient.js';
import { checkExposedPaths } from '../../src/scanner/checks/exposedPaths.js';

const mockFetchUrl = vi.mocked(fetchUrl);

function makeBaseResponse(): HttpResponse {
  return {
    status: 200,
    headers: {},
    body: '',
    url: 'https://example.com',
    redirectChain: [],
  };
}

function make404Response(): HttpResponse {
  return { ...makeBaseResponse(), status: 404 };
}

function make403Response(): HttpResponse {
  return { ...makeBaseResponse(), status: 403 };
}

describe('checkExposedPaths', () => {
  beforeEach(() => {
    mockFetchUrl.mockResolvedValue(make404Response());
  });

  it('returns no findings when all paths return 404', async () => {
    const findings = await checkExposedPaths('https://example.com', makeBaseResponse());
    expect(findings).toHaveLength(0);
  });

  it('flags /.env as critical when it returns 200', async () => {
    mockFetchUrl.mockImplementation(async (url: string) => {
      if (url.includes('/.env')) return makeBaseResponse(); // 200
      return make404Response();
    });

    const findings = await checkExposedPaths('https://example.com', makeBaseResponse());
    const envFinding = findings.find((f) => f.id.includes('-env-'));
    expect(envFinding).toBeDefined();
    expect(envFinding?.severity).toBe('critical');
  });

  it('flags /.git/config as critical when it returns 200', async () => {
    mockFetchUrl.mockImplementation(async (url: string) => {
      if (url.includes('/.git/config')) return makeBaseResponse(); // 200
      return make404Response();
    });

    const findings = await checkExposedPaths('https://example.com', makeBaseResponse());
    const gitFinding = findings.find((f) => f.id.includes('-git-config'));
    expect(gitFinding).toBeDefined();
    expect(gitFinding?.severity).toBe('critical');
  });

  it('flags /admin as critical when it returns 200', async () => {
    mockFetchUrl.mockImplementation(async (url: string) => {
      if (url.endsWith('/admin')) return makeBaseResponse(); // 200
      return make404Response();
    });

    const findings = await checkExposedPaths('https://example.com', makeBaseResponse());
    const adminFinding = findings.find((f) => f.id.includes('-admin'));
    expect(adminFinding).toBeDefined();
    expect(adminFinding?.severity).toBe('critical');
  });

  it('flags a path as medium when it returns 403', async () => {
    mockFetchUrl.mockImplementation(async (url: string) => {
      if (url.includes('/.htaccess')) return make403Response();
      return make404Response();
    });

    const findings = await checkExposedPaths('https://example.com', makeBaseResponse());
    const f = findings.find((f) => f.id.includes('-htaccess'));
    expect(f).toBeDefined();
    expect(f?.severity).toBe('medium');
  });

  it('flags /robots.txt as info (not critical) when it returns 200', async () => {
    mockFetchUrl.mockImplementation(async (url: string) => {
      if (url.includes('/robots.txt')) return makeBaseResponse(); // 200
      return make404Response();
    });

    const findings = await checkExposedPaths('https://example.com', makeBaseResponse());
    const f = findings.find((f) => f.id.includes('robots'));
    expect(f?.severity).toBe('info');
  });

  it('does not crash when a path probe throws a network error', async () => {
    mockFetchUrl.mockImplementation(async (url: string) => {
      if (url.includes('/.env')) throw new Error('ECONNREFUSED');
      return make404Response();
    });

    const findings = await checkExposedPaths('https://example.com', makeBaseResponse());
    // No finding for /.env since we couldn't reach it
    expect(findings.find((f) => f.id.includes('-env-'))).toBeUndefined();
  });

  it('uses the base URL (scheme + host) for path probing', async () => {
    const probedUrls: string[] = [];
    mockFetchUrl.mockImplementation(async (url: string) => {
      probedUrls.push(url);
      return make404Response();
    });

    await checkExposedPaths('https://example.com/some/deep/path', makeBaseResponse());

    // All probed URLs should be against the base domain, not the full path
    for (const url of probedUrls) {
      expect(url.startsWith('https://example.com/')).toBe(true);
      expect(url).not.toContain('/some/deep/path/');
    }
  });
});
