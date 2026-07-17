import { Router } from 'express';
import {
  scanController,
  getReportController,
  getPdfController,
  listScansController,
} from '../controllers/scan.controller.js';

export const scanRouter = Router();

/**
 * POST /scan
 * Body: { url: string }
 * Runs a full security scan and returns the ScanReport JSON.
 */
scanRouter.post('/scan', scanController);

/**
 * GET /scans
 * Returns a lightweight list of all stored scans (no findings, just metadata).
 */
scanRouter.get('/scans', listScansController);

/**
 * GET /scan/:id
 * Returns the full ScanReport JSON for the given scan ID.
 */
scanRouter.get('/scan/:id', getReportController);

/**
 * GET /scan/:id/report.pdf
 * Generates and downloads a PDF report for the given scan ID.
 */
scanRouter.get('/scan/:id/report.pdf', getPdfController);
