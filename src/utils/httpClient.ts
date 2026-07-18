import http from 'node:http';
import https from 'node:https';
import axios, { AxiosError } from 'axios';
import { env } from '../config/env.js';
import type { HttpResponse } from '../scanner/types.js';
import { safeLookup } from '../scanner/ssrfGuard.js';

const BODY_SIZE_LIMIT = 50 * 1024; // 50 KB

const httpAgent = new http.Agent({ lookup: safeLookup as any });
const httpsAgent = new https.Agent({ lookup: safeLookup as any });

/**
 * Makes a single GET request to `url` and returns a normalised HttpResponse.
 *
 * - Protected against SSRF and DNS Rebinding via custom DNS lookup.
 * - Follows redirects and records the chain.
 * - Truncates the body to 50 KB to avoid memory issues.
 * - Normalises all header names to lowercase.
 * - Never throws on HTTP errors (4xx/5xx) — those are valid responses to inspect.
 * - Throws only on network errors or timeouts.
 */
export async function fetchUrl(url: string, signal?: AbortSignal): Promise<HttpResponse> {
  const redirectChain: string[] = [];

  // Protocol validation before attempting any connection
  const parsed = new URL(url);
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(`Invalid protocol: ${parsed.protocol}. Only http and https are allowed.`);
  }

  const instance = axios.create({
    httpAgent,
    httpsAgent,
    timeout: env.HTTP_TIMEOUT_MS,
    maxRedirects: 10,
    maxContentLength: BODY_SIZE_LIMIT,
    maxBodyLength: BODY_SIZE_LIMIT,
    // We want raw headers so we can inspect them for security checks
    validateStatus: () => true, // never throw on HTTP status codes
    headers: {
      'User-Agent': 'Centinela-SecurityScanner/0.1 (+https://github.com/centinela)',
      Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    },
    // Track redirects
    beforeRedirect: (options: Record<string, unknown>, { headers }: { headers: Record<string, string> }) => {
      const location = headers['location'] as string | undefined;
      if (location) redirectChain.push(location);
    },
  });

  try {
    const response = await instance.get<string>(url, {
      responseType: 'text',
      signal,
    });

    // Normalise headers: lowercase keys, string values
    const headers: Record<string, string> = {};
    for (const [key, value] of Object.entries(response.headers)) {
      if (value !== undefined && value !== null) {
        headers[key.toLowerCase()] = Array.isArray(value) ? value.join(', ') : String(value);
      }
    }

    const body =
      typeof response.data === 'string'
        ? response.data.slice(0, BODY_SIZE_LIMIT)
        : '';

    return {
      status: response.status,
      headers,
      body,
      url: response.config.url ?? url,
      redirectChain,
    };
  } catch (err) {
    if (axios.isAxiosError(err)) {
      const msg = err.message.toLowerCase();
      // Axios may throw ERR_BAD_RESPONSE or ERR_FR_MAX_BODY_LENGTH without an err.response
      if (msg.includes('maxcontentlength') || msg.includes('maxbodylength')) {
        // NOTE: We access err.request.res (Node.js native IncomingMessage) instead of err.response
        // because when axios aborts mid-stream due to maxContentLength, it constructs the AxiosError
        // before the response object is fully hydrated — err.response ends up empty/undefined.
        // err.request.res is the raw Node.js response exposed through axios's internal HTTP adapter
        // and IS populated at this point. This is NOT part of axios's public API and could change
        // in a future major version without a semver notice. If upgrading axios, run
        // maxContentLength.test.ts first — that test acts as the canary for this code path.
        const rawHeaders = err.request?.res?.headers || err.response?.headers || {};
        const status = err.request?.res?.statusCode || err.response?.status || 200;
        const headers: Record<string, string> = {};
        for (const [key, value] of Object.entries(rawHeaders)) {
          if (value !== undefined && value !== null) {
            headers[key.toLowerCase()] = Array.isArray(value) ? value.join(', ') : String(value);
          }
        }
        return {
          status,
          headers,
          body: '',
          url: err.config?.url ?? url,
          redirectChain,
          truncated: true,
        };
      }
      throw new Error(
        `Network error scanning ${url}: ${err.message}` +
          (err.code ? ` (${err.code})` : ''),
      );
    }
    throw err;
  }
}
