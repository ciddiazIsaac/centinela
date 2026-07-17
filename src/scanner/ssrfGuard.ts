import dns from 'node:dns';
import net from 'node:net';

/**
 * Checks if an IP address belongs to a private, loopback, or cloud metadata range.
 */
export function isPrivateOrLocalIP(ip: string): boolean {
  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(Number);
    // 10.0.0.0/8 (Private)
    if (parts[0] === 10) return true;
    // 127.0.0.0/8 (Loopback)
    if (parts[0] === 127) return true;
    // 169.254.0.0/16 (Link-local / Cloud metadata)
    if (parts[0] === 169 && parts[1] === 254) return true;
    // 172.16.0.0/12 (Private)
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    // 192.168.0.0/16 (Private)
    if (parts[0] === 192 && parts[1] === 168) return true;
    // 0.0.0.0/8 (Current network)
    if (parts[0] === 0) return true;
  } else if (net.isIPv6(ip)) {
    const lower = ip.toLowerCase();
    // ::1/128 (Loopback)
    if (lower === '::1') return true;
    // fc00::/7 (Unique Local Address)
    if (lower.startsWith('fc') || lower.startsWith('fd')) return true;
    // fe80::/10 (Link-local)
    if (lower.startsWith('fe8') || lower.startsWith('fe9') || lower.startsWith('fea') || lower.startsWith('feb')) return true;
    // IPv4-mapped IPv6 addresses (e.g., ::ffff:127.0.0.1)
    if (lower.startsWith('::ffff:')) {
      const v4 = lower.split(':').pop();
      if (v4 && net.isIPv4(v4)) return isPrivateOrLocalIP(v4);
    }
  }
  return false;
}

/**
 * A custom DNS lookup function for Node's http/https agents.
 * This prevents SSRF and DNS Rebinding attacks by checking the resolved IP
 * at the exact moment the socket is about to connect.
 */
export const safeLookup: NodeJS.Dict<any> | any = (
  hostname: string,
  options: dns.LookupOptions | undefined,
  callback: (err: NodeJS.ErrnoException | null, address: string | dns.LookupAddress[], family: number) => void
) => {
  dns.lookup(hostname, options || {}, (err, address, family) => {
    if (err) return callback(err, address, family);

    // If options.all is true, address is an array of objects
    // Otherwise, address is a string
    const addresses = Array.isArray(address) ? address : [{ address }];

    for (const a of addresses) {
      if (isPrivateOrLocalIP(a.address)) {
        const error = new Error(`SSRF Blocked: Hostname ${hostname} resolves to private/internal IP ${a.address}`);
        return callback(error as NodeJS.ErrnoException, address, family);
      }
    }

    callback(null, address, family);
  });
};
