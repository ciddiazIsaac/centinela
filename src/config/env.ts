import 'dotenv/config';
import { z } from 'zod';

const envSchema = z.object({
  PORT: z
    .string()
    .default('3001')
    .transform((v) => parseInt(v, 10)),
  NODE_ENV: z
    .enum(['development', 'production', 'test'])
    .default('development'),
  HTTP_TIMEOUT_MS: z
    .string()
    .default('10000')
    .transform((v) => parseInt(v, 10)),
  MAX_STORED_SCANS: z
    .string()
    .default('100')
    .transform((v) => parseInt(v, 10)),
});

const parsed = envSchema.safeParse(process.env);

if (!parsed.success) {
  console.error('❌  Invalid environment variables:');
  console.error(parsed.error.flatten().fieldErrors);
  process.exit(1);
}

export const env = parsed.data;
