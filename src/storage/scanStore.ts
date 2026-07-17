import type { ScanReport } from '../scanner/types.js';
import { env } from '../config/env.js';

/**
 * In-memory scan store using a Map.
 *
 * Design: keeps only the N most recent scans (env.MAX_STORED_SCANS) to avoid
 * unbounded memory growth. Oldest entry is evicted when the limit is reached.
 *
 * Migration path: replace the Map with a DB client here without touching
 * any other module — controllers and routes call this interface exclusively.
 */
class ScanStore {
  private store = new Map<string, ScanReport>();

  save(report: ScanReport): void {
    // Evict oldest entry if limit reached
    if (this.store.size >= env.MAX_STORED_SCANS) {
      const oldestKey = this.store.keys().next().value;
      if (oldestKey) this.store.delete(oldestKey);
    }
    this.store.set(report.id, report);
  }

  get(id: string): ScanReport | undefined {
    return this.store.get(id);
  }

  list(): ScanReport[] {
    return Array.from(this.store.values()).reverse(); // newest first
  }

  count(): number {
    return this.store.size;
  }

  /** Wipe all stored scans. Used in tests. */
  clear(): void {
    this.store.clear();
  }
}

// Singleton instance shared across the app
export const scanStore = new ScanStore();
