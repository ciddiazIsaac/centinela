// ─── Severity levels ────────────────────────────────────────────────────────
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

// ─── A single detected issue ────────────────────────────────────────────────
export interface Finding {
  /** Machine-readable identifier, e.g. 'missing-csp' */
  id: string;
  title: string;
  severity: Severity;
  description: string;
  recommendation: string;
  /** Current value of the offending header / path, if applicable */
  evidence?: string;
}

// ─── Normalised HTTP response (one per scan) ─────────────────────────────────
export interface HttpResponse {
  status: number;
  headers: Record<string, string>;
  /** Raw response body (truncated to 50 KB) */
  body: string;
  /** Final URL after redirects */
  url: string;
  /** Chain of URLs visited during redirects */
  redirectChain: string[];
  /** Flag indicating if the response body was truncated due to size limits */
  truncated?: boolean;
}

// ─── Per-severity count ──────────────────────────────────────────────────────
export interface SeveritySummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

// ─── Complete scan report ────────────────────────────────────────────────────
export interface ScanReport {
  /** UUID v4 */
  id: string;
  /** URL that was scanned (original, before redirects) */
  url: string;
  /** ISO 8601 timestamp */
  scannedAt: string;
  /** Duration in milliseconds */
  duration: number;
  /**
   * Security score 0-100.
   * Starts at 100 and loses points per finding:
   *   critical -20 | high -10 | medium -5 | low -2 | info 0
   */
  score: number;
  findings: Finding[];
  summary: SeveritySummary;
}

// ─── Check function signature ────────────────────────────────────────────────
/**
 * Every check module exports a function with this exact shape.
 * engine.ts calls them all uniformly — no special-casing per check.
 *
 * NOTE: exposedPaths is the documented exception: it makes additional
 * HTTP requests internally, but its public signature is identical.
 */
export type CheckFn = (url: string, response: HttpResponse, signal?: AbortSignal) => Promise<Finding[]>;
