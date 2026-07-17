import PDFDocument from 'pdfkit';
import type { ScanReport, Severity } from '../scanner/types.js';

// ─── Color palette ───────────────────────────────────────────────────────────
const COLORS = {
  bg: '#0f0f1a',
  surface: '#1a1a2e',
  accent: '#6c63ff',
  critical: '#ff4757',
  high: '#ff6b35',
  medium: '#ffa502',
  low: '#2ed573',
  info: '#70a1ff',
  text: '#e2e8f0',
  muted: '#94a3b8',
  white: '#ffffff',
  border: '#2d2d44',
} as const;

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: COLORS.critical,
  high: COLORS.high,
  medium: COLORS.medium,
  low: COLORS.low,
  info: COLORS.info,
};

function scoreColor(score: number): string {
  if (score >= 80) return COLORS.low;
  if (score >= 60) return COLORS.medium;
  if (score >= 40) return COLORS.high;
  return COLORS.critical;
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString('es-AR', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    timeZoneName: 'short',
  });
}

/**
 * Generates a PDF security report from a ScanReport.
 * Returns the PDF as a Buffer.
 */
export function generatePdf(report: ScanReport): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];

    const doc = new PDFDocument({
      size: 'A4',
      margins: { top: 40, bottom: 40, left: 50, right: 50 },
      info: {
        Title: `Centinela Security Report — ${report.url}`,
        Author: 'Centinela Security Scanner',
        Subject: 'HTTP Security Audit Report',
        CreationDate: new Date(report.scannedAt),
      },
    });

    doc.on('data', (chunk: Buffer) => chunks.push(chunk));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);

    const W = doc.page.width - doc.page.margins.left - doc.page.margins.right;

    // ── Cover ─────────────────────────────────────────────────────────────────
    doc.rect(0, 0, doc.page.width, doc.page.height).fill(COLORS.bg);

    // Top accent bar
    doc.rect(0, 0, doc.page.width, 6).fill(COLORS.accent);

    // Logo / title area
    doc.moveDown(3);
    doc
      .fillColor(COLORS.accent)
      .fontSize(36)
      .font('Helvetica-Bold')
      .text('CENTINELA', { align: 'center' });

    doc
      .fillColor(COLORS.muted)
      .fontSize(13)
      .font('Helvetica')
      .text('HTTP Security Audit Report', { align: 'center' });

    doc.moveDown(2);

    // Score circle (rendered as filled circle)
    const scoreText = `${report.score}`;
    const cx = doc.page.width / 2;
    const cy = doc.y + 60;
    const r = 55;

    doc.circle(cx, cy, r).fill(COLORS.surface);
    doc.circle(cx, cy, r).stroke(scoreColor(report.score)).lineWidth(4);

    doc
      .fillColor(scoreColor(report.score))
      .fontSize(34)
      .font('Helvetica-Bold')
      .text(scoreText, cx - r, cy - 22, { width: r * 2, align: 'center' });

    doc
      .fillColor(COLORS.muted)
      .fontSize(9)
      .font('Helvetica')
      .text('SCORE', cx - r, cy + 16, { width: r * 2, align: 'center' });

    doc.moveDown(6);

    // Metadata box
    const metaY = cy + r + 30;
    doc.rect(doc.page.margins.left, metaY, W, 110).fill(COLORS.surface);

    const metaX = doc.page.margins.left + 20;
    const metaLabelW = 120;

    const metaLines = [
      ['URL', report.url],
      ['Scanned At', formatDate(report.scannedAt)],
      ['Duration', `${report.duration} ms`],
      ['Total Findings', `${report.findings.length}`],
    ];

    let currentY = metaY + 18;
    for (const [label, value] of metaLines) {
      doc
        .fillColor(COLORS.muted)
        .fontSize(9)
        .font('Helvetica-Bold')
        .text(label.toUpperCase(), metaX, currentY, { width: metaLabelW });
      doc
        .fillColor(COLORS.text)
        .fontSize(10)
        .font('Helvetica')
        .text(value, metaX + metaLabelW, currentY, { width: W - metaLabelW - 20 });
      currentY += 22;
    }

    // ── Summary section ───────────────────────────────────────────────────────
    doc.addPage();
    doc.rect(0, 0, doc.page.width, doc.page.height).fill(COLORS.bg);
    doc.rect(0, 0, doc.page.width, 6).fill(COLORS.accent);

    doc.y = 50;
    sectionTitle(doc, 'Findings Summary', COLORS.accent, W);

    const severities: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
    const cellW = W / severities.length;
    const cardY = doc.y + 10;
    const cardH = 70;

    for (let i = 0; i < severities.length; i++) {
      const sev = severities[i];
      const count = report.summary[sev];
      const color = SEVERITY_COLORS[sev];
      const cardX = doc.page.margins.left + i * cellW;

      doc.rect(cardX + 4, cardY, cellW - 8, cardH).fill(COLORS.surface);
      doc.rect(cardX + 4, cardY, cellW - 8, 4).fill(color);

      doc
        .fillColor(color)
        .fontSize(28)
        .font('Helvetica-Bold')
        .text(String(count), cardX + 4, cardY + 14, {
          width: cellW - 8,
          align: 'center',
        });

      doc
        .fillColor(COLORS.muted)
        .fontSize(8)
        .font('Helvetica')
        .text(sev.toUpperCase(), cardX + 4, cardY + 48, {
          width: cellW - 8,
          align: 'center',
        });
    }

    doc.y = cardY + cardH + 30;

    // ── Findings list ─────────────────────────────────────────────────────────
    if (report.findings.length === 0) {
      doc
        .fillColor(COLORS.low)
        .fontSize(14)
        .font('Helvetica-Bold')
        .text('🎉 No security issues detected!', { align: 'center' });
    } else {
      sectionTitle(doc, 'Detailed Findings', COLORS.accent, W);

      for (const finding of report.findings) {
        // Page break check
        if (doc.y > doc.page.height - 160) {
          doc.addPage();
          doc.rect(0, 0, doc.page.width, doc.page.height).fill(COLORS.bg);
          doc.rect(0, 0, doc.page.width, 6).fill(COLORS.accent);
          doc.y = 50;
        }

        const color = SEVERITY_COLORS[finding.severity];
        const cardStartY = doc.y;

        // Left severity bar
        doc.rect(doc.page.margins.left, cardStartY, 4, 1).fill(color); // placeholder, we'll extend after

        // Card background
        doc.rect(doc.page.margins.left + 6, cardStartY, W - 6, 10).fill(COLORS.surface);

        // Severity badge
        doc
          .fillColor(color)
          .fontSize(8)
          .font('Helvetica-Bold')
          .text(finding.severity.toUpperCase(), doc.page.margins.left + 14, cardStartY + 6);

        doc
          .fillColor(COLORS.muted)
          .fontSize(7)
          .font('Helvetica')
          .text(`  ·  ${finding.id}`, doc.page.margins.left + 60, cardStartY + 6);

        doc.y = cardStartY + 20;

        // Title
        doc
          .fillColor(COLORS.white)
          .fontSize(11)
          .font('Helvetica-Bold')
          .text(finding.title, doc.page.margins.left + 14, doc.y, {
            width: W - 20,
          });

        doc.moveDown(0.4);

        // Description
        doc
          .fillColor(COLORS.muted)
          .fontSize(9)
          .font('Helvetica')
          .text(finding.description, doc.page.margins.left + 14, doc.y, {
            width: W - 20,
          });

        doc.moveDown(0.4);

        // Recommendation
        doc
          .fillColor(COLORS.low)
          .fontSize(9)
          .font('Helvetica-Bold')
          .text('▶ Recommendation: ', doc.page.margins.left + 14, doc.y, {
            continued: true,
            width: W - 20,
          })
          .font('Helvetica')
          .fillColor(COLORS.text)
          .text(finding.recommendation);

        // Evidence (if present)
        if (finding.evidence) {
          doc.moveDown(0.3);
          doc
            .fillColor(COLORS.muted)
            .fontSize(8)
            .font('Helvetica-Oblique')
            .text(`Evidence: ${finding.evidence.slice(0, 120)}`, doc.page.margins.left + 14, doc.y, {
              width: W - 20,
            });
        }

        // Extend the left bar to actual card height
        const cardEndY = doc.y + 8;
        doc
          .rect(doc.page.margins.left, cardStartY, 4, cardEndY - cardStartY)
          .fill(color);

        doc.y = cardEndY + 10;
      }
    }

    // ── Footer ────────────────────────────────────────────────────────────────
    const totalPages = (doc.bufferedPageRange().count);
    for (let i = 0; i < totalPages; i++) {
      doc.switchToPage(i);
      doc
        .fillColor(COLORS.muted)
        .fontSize(7)
        .text(
          `Centinela Security Scanner  ·  Page ${i + 1} of ${totalPages}  ·  ${report.url}`,
          doc.page.margins.left,
          doc.page.height - 30,
          { width: W, align: 'center' },
        );
    }

    doc.end();
  });
}

// ─── Helper ───────────────────────────────────────────────────────────────────
function sectionTitle(
  doc: InstanceType<typeof PDFDocument>,
  title: string,
  color: string,
  width: number,
): void {
  doc
    .fillColor(color)
    .fontSize(14)
    .font('Helvetica-Bold')
    .text(title, { width });
  doc.moveDown(0.3);
  doc
    .rect(doc.page.margins.left, doc.y, width, 1)
    .fill(color);
  doc.moveDown(1);
}
