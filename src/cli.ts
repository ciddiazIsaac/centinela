#!/usr/bin/env node
import { Command } from 'commander';
import { scan } from './scanner/engine.js';
import { generatePdf } from './report/pdfGenerator.js';
import { writeFileSync } from 'fs';
import type { ScanReport, Severity } from './scanner/types.js';

import pc from 'picocolors';

const program = new Command();

program
  .name('centinela')
  .description('🛡️  HTTP security scanner — checks headers, CORS, cookies & exposed paths')
  .version('0.1.0');

// ── centinela scan <url> ──────────────────────────────────────────────────────
program
  .command('scan <url>')
  .description('Scan a URL and report security findings')
  .option('-j, --json', 'Output raw JSON instead of formatted table')
  .option('-o, --output <file>', 'Save PDF report to file (e.g. report.pdf)')
  .option('-q, --quiet', 'Only show score and finding counts')
  .action(async (url: string, opts: { json?: boolean; output?: string; quiet?: boolean }) => {
    // Validate URL
    try {
      new URL(url);
    } catch {
      console.error(pc.red(`\n❌  Invalid URL: ${url}`));
      console.error(pc.gray('    Include the protocol: https://example.com'));
      process.exit(1);
    }

    console.error(pc.cyan(`\n🛡️  Centinela — scanning ${pc.bold(url)} ...\n`));

    let report: ScanReport;
    try {
      report = await scan(url);
    } catch (err) {
      console.error(pc.red(`\n❌  Scan failed: ${(err as Error).message}`));
      process.exit(1);
    }

    // ── JSON mode ──────────────────────────────────────────────────────────
    if (opts.json) {
      console.log(JSON.stringify(report, null, 2));
      if (opts.output) await savePdf(report, opts.output);
      return;
    }

    // ── Formatted output ───────────────────────────────────────────────────
    printReport(report, opts.quiet ?? false);

    if (opts.output) await savePdf(report, opts.output);
  });

program.parse();

// ─── Helpers ─────────────────────────────────────────────────────────────────

function severityColor(sev: Severity): string {
  const map: Record<Severity, string> = {
    critical: pc.red(pc.bold(sev.toUpperCase())),
    high: pc.bold(sev.toUpperCase()), // picocolors lacks hex, we'll just bold it or use magenta/yellow
    medium: pc.yellow(pc.bold(sev.toUpperCase())),
    low: pc.green(sev.toUpperCase()),
    info: pc.blue(sev.toUpperCase()),
  };
  return map[sev] ?? sev;
}

function scoreEmoji(score: number): string {
  if (score >= 80) return '🟢';
  if (score >= 60) return '🟡';
  if (score >= 40) return '🟠';
  return '🔴';
}

function printReport(report: ScanReport, quiet: boolean): void {
  const { score, summary, findings, url, scannedAt, duration } = report;

  // Header
  console.log(pc.bold('─'.repeat(60)));
  console.log(`  ${scoreEmoji(score)} Score: ${pc.bold(String(score))}/100   (${duration}ms)`);
  console.log(`  🌐 ${pc.cyan(url)}`);
  console.log(`  🕒 ${new Date(scannedAt).toLocaleString()}`);
  console.log(pc.bold('─'.repeat(60)));

  // Summary row
  const s = summary;
  const parts = [
    s.critical > 0 ? pc.red(pc.bold(`${s.critical} critical`)) : null,
    s.high > 0 ? pc.bold(`${s.high} high`) : null, // picocolors lacks hex
    s.medium > 0 ? pc.yellow(`${s.medium} medium`) : null,
    s.low > 0 ? pc.green(`${s.low} low`) : null,
    s.info > 0 ? pc.blue(`${s.info} info`) : null,
  ].filter(Boolean);

  if (parts.length === 0) {
    console.log(pc.green(pc.bold('  ✅ No security issues found!')));
  } else {
    console.log('  Findings: ' + parts.join(pc.gray(' · ')));
  }

  if (quiet || findings.length === 0) {
    console.log();
    return;
  }

  // Findings detail
  console.log(pc.bold('\n  Findings:\n'));
  for (const f of findings) {
    console.log(`  ${severityColor(f.severity).padEnd(20)} ${pc.white(pc.bold(f.title))}`);
    console.log(`  ${pc.gray('  ' + f.description.slice(0, 120) + (f.description.length > 120 ? '...' : ''))}`);
    console.log(`  ${pc.cyan('  ▶ ' + f.recommendation.slice(0, 100) + (f.recommendation.length > 100 ? '...' : ''))}`);
    if (f.evidence) {
      console.log(`  ${pc.gray('  Evidence: ' + f.evidence.slice(0, 80))}`);
    }
    console.log();
  }

  console.log(pc.bold('─'.repeat(60)));
  console.log(pc.gray(`  Report ID: ${report.id}`));
  console.log();
}

async function savePdf(report: ScanReport, outputPath: string): Promise<void> {
  try {
    const { generatePdf } = await import('./report/pdfGenerator.js');
    const buffer = await generatePdf(report);
    writeFileSync(outputPath, buffer);
    console.error(pc.green(`\n📄 PDF saved to: ${outputPath}`));
  } catch (err) {
    console.error(pc.red(`\n❌ Failed to generate PDF: ${(err as Error).message}`));
  }
}
