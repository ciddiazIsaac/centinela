import { describe, it, expect, vi } from 'vitest';
import { isPrivateOrLocalIP, safeLookup } from '../src/scanner/ssrfGuard.js';
import dns from 'node:dns';

describe('SSRF Guard - isPrivateOrLocalIP', () => {
  it('permits normal public IPs', () => {
    expect(isPrivateOrLocalIP('8.8.8.8')).toBe(false);
    expect(isPrivateOrLocalIP('104.21.5.1')).toBe(false);
    expect(isPrivateOrLocalIP('142.250.190.46')).toBe(false);
    expect(isPrivateOrLocalIP('2606:4700:4700::1111')).toBe(false); // Cloudflare public v6
  });

  it('blocks localhost / loopback', () => {
    expect(isPrivateOrLocalIP('127.0.0.1')).toBe(true);
    expect(isPrivateOrLocalIP('127.255.255.254')).toBe(true);
    expect(isPrivateOrLocalIP('::1')).toBe(true);
  });

  it('blocks 0.0.0.0 (current network / any IPv4)', () => {
    expect(isPrivateOrLocalIP('0.0.0.0')).toBe(true);
  });

  it('blocks mapped IPv4 loopbacks (::ffff:127.0.0.1)', () => {
    expect(isPrivateOrLocalIP('::ffff:127.0.0.1')).toBe(true);
    expect(isPrivateOrLocalIP('::ffff:10.0.0.1')).toBe(true);
  });

  it('blocks 10.x.x.x private range', () => {
    expect(isPrivateOrLocalIP('10.0.0.1')).toBe(true);
    expect(isPrivateOrLocalIP('10.255.255.255')).toBe(true);
  });

  it('blocks 172.16.x.x - 172.31.x.x private range', () => {
    expect(isPrivateOrLocalIP('172.16.0.0')).toBe(true);
    expect(isPrivateOrLocalIP('172.31.255.255')).toBe(true);
    
    // Normal public IP starting with 172 should pass
    expect(isPrivateOrLocalIP('172.32.0.1')).toBe(false);
    expect(isPrivateOrLocalIP('172.15.255.255')).toBe(false);
  });

  it('blocks 192.168.x.x private range', () => {
    expect(isPrivateOrLocalIP('192.168.0.1')).toBe(true);
    expect(isPrivateOrLocalIP('192.168.255.255')).toBe(true);
  });

  it('blocks 169.254.169.254 explicit cloud metadata endpoint', () => {
    expect(isPrivateOrLocalIP('169.254.169.254')).toBe(true);
    expect(isPrivateOrLocalIP('169.254.0.1')).toBe(true); // whole range is link-local
  });

  it('blocks IPv6 Unique Local Addresses (fc00::/7)', () => {
    expect(isPrivateOrLocalIP('fc00::1')).toBe(true);
    expect(isPrivateOrLocalIP('fd12:3456:789a:1::1')).toBe(true);
  });
});

describe('SSRF Guard - safeLookup custom DNS', () => {
  it('allows lookup for a domain resolving to public IP', () => {
    const mockLookup = vi.spyOn(dns, 'lookup').mockImplementation(((hostname: string, options: any, cb?: any) => {
      const callback = typeof options === 'function' ? options : cb;
      callback(null, [{ address: '8.8.8.8', family: 4 }]);
    }) as any);

    safeLookup('google.com', { all: true }, (err: any, addresses: any) => {
      expect(err).toBeNull();
      expect(addresses[0].address).toBe('8.8.8.8');
    });

    mockLookup.mockRestore();
  });

  it('aborts lookup for a domain resolving to private IP', () => {
    const mockLookup = vi.spyOn(dns, 'lookup').mockImplementation(((hostname: string, options: any, cb?: any) => {
      const callback = typeof options === 'function' ? options : cb;
      callback(null, [{ address: '192.168.1.1', family: 4 }]);
    }) as any);

    safeLookup('internal.company.local', { all: true }, (err: any) => {
      expect(err).toBeDefined();
      expect(err.message).toContain('SSRF Blocked');
      expect(err.message).toContain('192.168.1.1');
    });

    mockLookup.mockRestore();
  });

  it('aborts lookup if ANY resolved IP is private', () => {
    const mockLookup = vi.spyOn(dns, 'lookup').mockImplementation(((hostname: string, options: any, cb?: any) => {
      const callback = typeof options === 'function' ? options : cb;
      callback(null, [
        { address: '8.8.8.8', family: 4 },
        { address: '127.0.0.1', family: 4 }
      ]);
    }) as any);

    safeLookup('malicious-rebinding.com', { all: true }, (err: any) => {
      expect(err).toBeDefined();
      expect(err.message).toContain('SSRF Blocked');
      expect(err.message).toContain('127.0.0.1');
    });

    mockLookup.mockRestore();
  });
});
