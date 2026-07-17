import { Request, Response } from 'express';
import { z } from 'zod';
import { scan } from '../scanner/engine.js';
import { scanStore } from '../storage/scanStore.js';
import { generatePdf } from '../report/pdfGenerator.js';

// ─── Validation schema ────────────────────────────────────────────────────────
const scanBodySchema = z.object({
  url: z
    .string({ required_error: 'url is required' })
    .url({ message: 'url must be a valid URL (include http:// or https://)' })
    .refine((u) => u.startsWith('http://') || u.startsWith('https://'), {
      message: 'url must use http or https protocol',
    }),
});

// ─── POST /scan ───────────────────────────────────────────────────────────────
export async function scanController(req: Request, res: Response): Promise<void> {
  const parsed = scanBodySchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({
      error: 'Validation error',
      details: parsed.error.flatten().fieldErrors,
    });
    return;
  }

  const { url } = parsed.data;

  const report = await scan(url);
  scanStore.save(report);

  res.status(200).json(report);
}

// ─── GET /scan/:id ────────────────────────────────────────────────────────────
export function getReportController(req: Request, res: Response): void {
  const { id } = req.params;
  const report = scanStore.get(id);

  if (!report) {
    res.status(404).json({ error: `Scan '${id}' not found` });
    return;
  }

  res.json(report);
}

// ─── GET /scan/:id/report.pdf ─────────────────────────────────────────────────
export async function getPdfController(req: Request, res: Response): Promise<void> {
  const { id } = req.params;
  const report = scanStore.get(id);

  if (!report) {
    res.status(404).json({ error: `Scan '${id}' not found` });
    return;
  }

  const pdfBuffer = await generatePdf(report);

  const filename = `centinela-report-${id.slice(0, 8)}.pdf`;
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.setHeader('Content-Length', pdfBuffer.length);
  res.send(pdfBuffer);
}

// ─── GET /scans ───────────────────────────────────────────────────────────────
export function listScansController(_req: Request, res: Response): void {
  const scans = scanStore.list().map(({ id, url, scannedAt, score, summary }) => ({
    id,
    url,
    scannedAt,
    score,
    summary,
  }));
  res.json({ count: scans.length, scans });
}
