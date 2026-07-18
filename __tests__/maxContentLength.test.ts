import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import { scan } from '../src/scanner/engine.js';
import http from 'http';
import { AddressInfo } from 'net';

vi.mock('../src/scanner/ssrfGuard.js', () => ({
  safeLookup: (hostname: string, options: any, cb: any) => {
    // Just blindly resolve to 127.0.0.1 for this test
    cb(null, [{ address: '127.0.0.1', family: 4 }]);
  },
  isPrivateOrLocalIP: () => false,
}));

describe('maxContentLength protection', () => {
  let server: http.Server;
  let port: number;

  beforeAll(async () => {
    // Create a local server that responds with more than 50KB of data
    server = http.createServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      // Send 100KB of data
      const chunk = 'a'.repeat(1024);
      let count = 0;
      const interval = setInterval(() => {
        res.write(chunk);
        count++;
        if (count >= 100) {
          clearInterval(interval);
          res.end();
        }
      }, 5);
    });

    await new Promise<void>((resolve) => {
      server.listen(0, () => {
        port = (server.address() as AddressInfo).port;
        resolve();
      });
    });
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
  });

  it('should abort download and report truncated response finding when server sends too much data', async () => {
    const url = `http://127.0.0.1:${port}/`;
    const report = await scan(url);
    
    // We expect the scan to finish without throwing an unhandled exception
    // AND it should include the info finding for truncated response
    
    const truncatedFinding = report.findings.find(f => f.id === 'response-truncated');
    expect(truncatedFinding).toBeDefined();
    expect(truncatedFinding?.severity).toBe('info');
  });
});
