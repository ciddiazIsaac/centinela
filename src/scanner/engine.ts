import crypto from 'node:crypto';
import { fetchUrl } from '../utils/httpClient.js';
import { checkSecurityHeaders } from './checks/securityHeaders.js';
import { checkCors } from './checks/cors.js';
import { checkCookies } from './checks/cookies.js';
import { checkExposedPaths } from './checks/exposedPaths.js';
import type { CheckFn, Finding, ScanReport, SeveritySummary } from './types.js';

// ─── Penalty weights for score calculation ───────────────────────────────────
const PENALTIES: Record<string, number> = {
  critical: 20,
  high: 10,
  medium: 5,
  low: 2,
  info: 0,
};

// ─── All registered checks ───────────────────────────────────────────────────
// To add a new check: create a file in checks/ and add it here. That's it.
const CHECKS: CheckFn[] = [
  checkSecurityHeaders,
  checkCors,
  checkCookies,
  checkExposedPaths,
];

function buildSummary(findings: Finding[]): SeveritySummary {
  return findings.reduce<SeveritySummary>(
    (acc, f) => {
      acc[f.severity]++;
      return acc;
    },
    { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  );
}

function calculateScore(findings: Finding[]): number {
  const totalPenalty = findings.reduce(
    (sum, f) => sum + (PENALTIES[f.severity] ?? 0),
    0,
  );
  return Math.max(0, 100 - totalPenalty);
}

/**
 * Runs a full security scan against `url`.
 *
 * 1. Makes ONE HTTP request to the target URL.
 * 2. Passes the response to all checks in parallel.
 * 3. Aggregates findings, computes score, and returns a ScanReport.
 *
 * Note: checkExposedPaths makes additional requests internally (by design).
 */
export async function scan(url: string): Promise<ScanReport> {
  const startTime = Date.now();

  const controller = new AbortController();
  const globalTimeout = setTimeout(() => controller.abort(), 30000); // 30 seconds global timeout

  try {
    // ── Single HTTP request ──────────────────────────────────────────────────
    const httpResponse = await fetchUrl(url, controller.signal);

    // ── Run all checks in parallel ───────────────────────────────────────────
    const checkResults = await Promise.allSettled(
      CHECKS.map((check) => check(url, httpResponse, controller.signal)),
    );

    // Collect findings, logging any check errors but not crashing
    const findings: Finding[] = [];
    for (const result of checkResults) {
      if (result.status === 'fulfilled') {
        findings.push(...result.value);
      } else {
        console.error('[engine] check failed:', result.reason);
      }
    }

    if (httpResponse.truncated) {
      findings.push({
        id: 'response-truncated',
        title: 'Response exceeded maximum size',
        severity: 'info',
        description: 'The HTTP response exceeded the maximum permitted size of 50KB. The download was aborted to protect server resources. The scan was performed on the headers and a truncated body.',
        recommendation: 'Verify the endpoint is behaving correctly and not leaking memory or returning unexpected huge payloads.',
      });
    }

    // Sort findings by severity (critical first)
    const severityOrder: Record<string, number> = {
      critical: 0,
      high: 1,
      medium: 2,
      low: 3,
      info: 4,
    };
    findings.sort((a, b) => (severityOrder[a.severity] ?? 99) - (severityOrder[b.severity] ?? 99));

    const duration = Date.now() - startTime;
    const summary = buildSummary(findings);
    const score = calculateScore(findings);

    return {
      id: crypto.randomUUID(),
      url,
      scannedAt: new Date().toISOString(),
      duration,
      score,
      findings,
      summary,
    };
  } finally {
    clearTimeout(globalTimeout);
  }
}
