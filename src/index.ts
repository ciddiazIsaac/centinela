import 'express-async-errors';
import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import path from 'path';
import { fileURLToPath } from 'url';
import { env } from './config/env.js';
import { scanRouter } from './routes/scan.routes.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const app = express();

// ── Security middleware ───────────────────────────────────────────────────────
app.use(helmet());
app.use(cors());

// ── Rate limiting ─────────────────────────────────────────────────────────────
// Scanning is expensive; limit to 10 scans per minute per IP
const scanLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: { error: 'Too many scan requests, please try again in a minute.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// ── Body parsing ──────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// ── Static files (landing page) ───────────────────────────────────────────────
app.use(express.static(path.join(__dirname, '..', 'public')));

// ── API routes ────────────────────────────────────────────────────────────────
app.use('/api', scanLimiter, scanRouter);

// ── Health check ──────────────────────────────────────────────────────────────
app.get('/health', (_req, res) => {
  res.json({ status: 'ok', version: '0.1.0' });
});

// ── Global error handler ──────────────────────────────────────────────────────
// eslint-disable-next-line @typescript-eslint/no-unused-vars
app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  console.error('[error]', err.message);
  const status = (err as Error & { status?: number }).status ?? 500;
  res.status(status).json({
    error: env.NODE_ENV === 'production' ? 'Internal server error' : err.message,
  });
});

// ── Start ──────────────────────────────────────────────────────────────────────
app.listen(env.PORT, () => {
  console.log(`\n🛡️  Centinela running on http://localhost:${env.PORT}`);
  console.log(`   API: http://localhost:${env.PORT}/api/scan`);
  console.log(`   POST /api/scan        → run a scan`);
  console.log(`   GET  /api/scan/:id    → get report JSON`);
  console.log(`   GET  /api/scan/:id/report.pdf → download PDF\n`);
});

export default app;
