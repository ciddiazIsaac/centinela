import { fetchUrl } from '../../utils/httpClient.js';
import type { CheckFn, Finding } from '../types.js';

/**
 * Sensitive paths to probe.
 *
 * Architecture note: This check is the documented exception to the "one HTTP
 * request per scan" rule. It makes additional requests internally because it
 * needs to probe multiple paths — but its public signature (CheckFn) is
 * identical to every other check. engine.ts treats it uniformly.
 */
const SENSITIVE_PATHS: Array<{ path: string; description: string }> = [
  { path: '/.env',            description: 'Environment variables file' },
  { path: '/.env.local',      description: 'Local environment variables file' },
  { path: '/.env.production', description: 'Production environment variables file' },
  { path: '/.git/config',     description: 'Git repository configuration' },
  { path: '/.git/HEAD',       description: 'Git HEAD reference file' },
  { path: '/admin',           description: 'Admin panel' },
  { path: '/administrator',   description: 'Administrator panel' },
  { path: '/phpinfo.php',     description: 'PHP configuration disclosure page' },
  { path: '/wp-admin',        description: 'WordPress admin panel' },
  { path: '/wp-config.php',   description: 'WordPress configuration file' },
  { path: '/.DS_Store',       description: 'macOS directory metadata file' },
  { path: '/backup.zip',      description: 'Site backup archive' },
  { path: '/backup.tar.gz',   description: 'Site backup archive (gzip)' },
  { path: '/config.json',     description: 'Application configuration file' },
  { path: '/config.yml',      description: 'Application configuration file (YAML)' },
  { path: '/.htaccess',       description: 'Apache configuration file' },
  { path: '/server-status',   description: 'Apache server status page' },
  { path: '/server-info',     description: 'Apache server info page' },
  { path: '/web.config',      description: 'IIS configuration file' },
  { path: '/robots.txt',      description: 'Robots exclusion file (info only)' },
  { path: '/sitemap.xml',     description: 'Sitemap (info only)' },
];

/**
 * Extracts the base URL (scheme + host) from a full URL.
 */
function getBaseUrl(url: string): string {
  try {
    const parsed = new URL(url);
    return `${parsed.protocol}//${parsed.host}`;
  } catch {
    return url;
  }
}

export const checkExposedPaths: CheckFn = async (url, _response) => {
  const findings: Finding[] = [];
  const baseUrl = getBaseUrl(url);

  // Probe all paths in parallel with a concurrency limit of 5
  const CONCURRENCY = 5;
  const results: Array<{ path: string; description: string; status: number }> = [];

  for (let i = 0; i < SENSITIVE_PATHS.length; i += CONCURRENCY) {
    const batch = SENSITIVE_PATHS.slice(i, i + CONCURRENCY);
    const batchResults = await Promise.all(
      batch.map(async ({ path, description }) => {
        try {
          const res = await fetchUrl(`${baseUrl}${path}`);
          return { path, description, status: res.status };
        } catch {
          // Network error → can't access, not exposed
          return { path, description, status: -1 };
        }
      }),
    );
    results.push(...batchResults);
  }

  for (const { path, description, status } of results) {
    if (status === 200) {
      // Directly accessible → critical (except informational paths)
      const isInfoOnly = path === '/robots.txt' || path === '/sitemap.xml';
      findings.push({
        id: `exposed-path-${path.replace(/[^a-z0-9]/gi, '-')}`,
        title: `Sensitive path accessible: ${path}`,
        severity: isInfoOnly ? 'info' : 'critical',
        description: `The path '${path}' (${description}) returned HTTP 200, meaning it is publicly accessible. This may expose sensitive data or configuration details.`,
        recommendation: isInfoOnly
          ? `Review the contents of '${path}' to ensure it doesn't expose sensitive information.`
          : `Immediately restrict access to '${path}'. Remove the file from the web root or configure your server to block access to it.`,
        evidence: `${baseUrl}${path} → HTTP 200`,
      });
    } else if (status === 403) {
      // Exists but blocked → medium (the path exists, just ACL-protected)
      const isInfoOnly = path === '/robots.txt' || path === '/sitemap.xml';
      if (!isInfoOnly) {
        findings.push({
          id: `blocked-path-${path.replace(/[^a-z0-9]/gi, '-')}`,
          title: `Sensitive path exists but is access-controlled: ${path}`,
          severity: 'medium',
          description: `The path '${path}' (${description}) returned HTTP 403. The resource exists but access is currently blocked by the server. Misconfigurations could make it accessible.`,
          recommendation: `Verify that '${path}' is intentionally present and that the access controls are robust. Consider removing the file entirely from the web root.`,
          evidence: `${baseUrl}${path} → HTTP 403`,
        });
      }
    }
    // 404, -1, and other codes → path not found or unreachable, no finding
  }

  return findings;
};
