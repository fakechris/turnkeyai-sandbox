import { describe, expect, it } from 'vitest';
import {
    createHostProxy,
    parseHostPort,
    parseSocksRequest,
} from '../../../src/sandbox/network/host-proxy.js';

describe('parseHostPort', () => {
    it('parses bare host', () => {
        expect(parseHostPort('example.com', 80)).toEqual({ host: 'example.com', port: 80 });
    });

    it('parses host:port', () => {
        expect(parseHostPort('example.com:8080', 80)).toEqual({ host: 'example.com', port: 8080 });
    });

    it('parses IPv4:port', () => {
        expect(parseHostPort('127.0.0.1:3128', 80)).toEqual({ host: '127.0.0.1', port: 3128 });
    });

    it('parses bracketed IPv6 with port', () => {
        expect(parseHostPort('[::1]:443', 80)).toEqual({ host: '::1', port: 443 });
    });

    it('parses bare IPv6 (no brackets) by treating the trailing digits as the port', () => {
        // 's parseHostPort uses lastIndexOf(':') and then Number()s the
        // trailing chunk. This means unbracketed IPv6 like '::1' will be
        // misread as host=':' + port=1. This is a bug, faithfully
        // preserved here. Always use brackets for IPv6 + port.
        const r = parseHostPort('::1', 80);
        expect(r.port).toBe(1);
        expect(r.host).toBe(':');
    });
});

describe('parseSocksRequest', () => {
    it('returns undefined for too-short buffers', () => {
        expect(parseSocksRequest(Buffer.alloc(0))).toBeUndefined();
        expect(parseSocksRequest(Buffer.from([0x05]))).toBeUndefined();
    });

    it('returns null for wrong SOCKS version', () => {
        const buf = Buffer.from([0x04, 0x01, 0x00, 0x01]);
        expect(parseSocksRequest(buf)).toBeNull();
    });

    it('returns null for non-CONNECT command', () => {
        const buf = Buffer.from([0x05, 0x02, 0x00, 0x01, 1, 2, 3, 4, 0, 80]);
        expect(parseSocksRequest(buf)).toBeNull();
    });

    it('parses IPv4 CONNECT', () => {
        const buf = Buffer.from([
            0x05, 0x01, 0x00, 0x01,
            127, 0, 0, 1,
            0x1f, 0x90, // 8080
        ]);
        const r = parseSocksRequest(buf);
        expect(r).toEqual({ host: '127.0.0.1', port: 8080, consumed: 10 });
    });

    it('parses domain CONNECT', () => {
        const host = 'example.com';
        const buf = Buffer.alloc(7 + host.length);
        buf[0] = 0x05;
        buf[1] = 0x01;
        buf[2] = 0x00;
        buf[3] = 0x03; // domain
        buf[4] = host.length;
        buf.write(host, 5, 'ascii');
        buf.writeUInt16BE(443, 5 + host.length);
        const r = parseSocksRequest(buf);
        expect(r).toEqual({ host: 'example.com', port: 443, consumed: 5 + host.length + 2 });
    });

    it('parses IPv6 CONNECT', () => {
        const buf = Buffer.alloc(22);
        buf[0] = 0x05;
        buf[1] = 0x01;
        buf[2] = 0x00;
        buf[3] = 0x04; // IPv6
        // 16 bytes of IPv6 (zero-filled)
        buf.writeUInt16BE(0, 4);
        buf.writeUInt16BE(0, 6);
        buf.writeUInt16BE(0, 8);
        buf.writeUInt16BE(0, 10);
        buf.writeUInt16BE(0, 12);
        buf.writeUInt16BE(0, 14);
        buf.writeUInt16BE(0, 16);
        buf.writeUInt16BE(0, 18);
        buf.writeUInt16BE(443, 20);
        const r = parseSocksRequest(buf);
        expect(r?.port).toBe(443);
        expect(r?.consumed).toBe(22);
    });
});

describe('createHostProxy (integration: real loopback sockets)', () => {
    it('binds to an ephemeral port and exposes http+socks ports', async () => {
        const proxy = createHostProxy({ allowedHosts: ['example.com'] });
        await proxy.start();
        expect(proxy.httpPort).toBeGreaterThan(0);
        expect(proxy.socksPort).toBeGreaterThan(0);
        expect(proxy.isRunning).toBe(true);
        await proxy.stop();
        expect(proxy.isRunning).toBe(false);
    });

    it('refuses unknown host on HTTP CONNECT (403)', async () => {
        const proxy = createHostProxy({ allowedHosts: ['example.com'] });
        await proxy.start();
        try {
            const status = await new Promise<number>((resolve, reject) => {
                import('node:net').then((net) => {
                    const sock = net.connect(proxy.httpPort, '127.0.0.1', () => {
                        sock.write(
                            'CONNECT evil.com:443 HTTP/1.1\r\nHost: evil.com:443\r\n\r\n',
                        );
                    });
                    let buf = '';
                    sock.on('data', (c) => (buf += c.toString()));
                    sock.on('end', () => resolve(parseHttpStatus(buf)));
                    sock.on('error', reject);
                });
            });
            expect(status).toBe(403);
        } finally {
            await proxy.stop();
        }
    });

    it('accepts allowed host on HTTP CONNECT (200)', async () => {
        const proxy = createHostProxy({ allowedHosts: ['example.com'] });
        await proxy.start();
        try {
            const status = await new Promise<number>((resolve, reject) => {
                import('node:net').then((net) => {
                    const sock = net.connect(proxy.httpPort, '127.0.0.1', () => {
                        sock.write(
                            'CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n',
                        );
                    });
                    let buf = '';
                    sock.on('data', (c) => (buf += c.toString()));
                    sock.on('end', () => resolve(parseHttpStatus(buf)));
                    sock.on('error', reject);
                });
            });
            // We get 200 because the proxy says "connection established" — the
            // subsequent upstream connect to example.com:443 may fail with
            // ECONNREFUSED locally, which is irrelevant to the proxy's
            // accept/deny decision.
            expect(status).toBe(200);
        } finally {
            await proxy.stop();
        }
    });

    it('askCallback is invoked for unknown hosts', async () => {
        let asked = false;
        const proxy = createHostProxy({
            allowedHosts: ['example.com'],
            askCallback: async (host, _port) => {
                asked = host === 'unknown.com';
                return false; // deny
            },
        });
        await proxy.start();
        try {
            await new Promise<void>((resolve, reject) => {
                import('node:net').then((net) => {
                    const sock = net.connect(proxy.httpPort, '127.0.0.1', () => {
                        sock.write(
                            'CONNECT unknown.com:443 HTTP/1.1\r\nHost: unknown.com:443\r\n\r\n',
                        );
                    });
                    sock.on('data', () => {
                        /* ignore */
                    });
                    sock.on('end', () => resolve());
                    sock.on('error', reject);
                });
            });
            // Give the async askCallback time to fire
            await new Promise((r) => setTimeout(r, 100));
            expect(asked).toBe(true);
        } finally {
            await proxy.stop();
        }
    });

    it('httpOnly skips the SOCKS5 server', async () => {
        const proxy = createHostProxy({
            allowedHosts: ['example.com'],
            httpOnly: true,
        });
        await proxy.start();
        expect(proxy.httpPort).toBeGreaterThan(0);
        expect(proxy.socksPort).toBe(0);
        expect(() => proxy._socksServer).toThrow();
        await proxy.stop();
    });
});

function parseHttpStatus(raw: string): number {
    const first = raw.split('\r\n')[0] ?? '';
    const m = /HTTP\/1\.[01] (\d+)/.exec(first);
    if (!m) {
        return 0;
    }
    return Number(m[1]);
}
