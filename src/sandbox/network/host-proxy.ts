/**
 * HTTP + SOCKS5 dual-stack host proxy.
 *
 * Reverse-engineered from
 * `packages/sandbox/src/network/host-proxy.ts` .
 *
 * Runs on loopback (127.0.0.1), enforces an `allowedHosts` allowlist, and
 * optionally delegates unknown hosts to an `askCallback` for interactive
 * approval. Both an HTTP proxy (plain HTTP forward + CONNECT tunnel) and a
 * SOCKS5 proxy (no-auth + CONNECT) are exposed.
 *
 * @public
 */

import { createServer as createHttpServer, request as httpRequest, type Server as HttpServer } from 'node:http';
import { createServer as createNetServer, connect as netConnect, type Server as NetServer } from 'node:net';

/** Async hook for unknown-host approval. Resolves true to allow. */
export type AskCallback = (host: string, port: number) => Promise<boolean> | boolean;

/** Parsed `host:port` pair. */
export interface HostPort {
    host: string;
    port: number;
}

/** Public options for {@link createHostProxy}. */
export interface HostProxyOptions {
    allowedHosts: readonly string[];
    askCallback?: AskCallback;
    /**
     * Port for both servers to listen on. Defaults to `0` (ephemeral).
     * Set to a positive integer to pin a specific port.
     */
    listenPort?: number;
    /**
     * If true, only start the HTTP server (skip SOCKS5). Useful when the
     * caller only needs HTTP proxying.
     */
    httpOnly?: boolean;
}

/** Public handle returned by {@link createHostProxy}. */
export interface HostProxyHandle {
    readonly httpPort: number;
    readonly socksPort: number;
    readonly isRunning: boolean;
    start(): Promise<void>;
    stop(): Promise<void>;
    /** Internal HTTP server (for testing). */
    readonly _httpServer: HttpServer;
    /** Internal SOCKS5 server (for testing). */
    readonly _socksServer: NetServer;
}

// ─── SOCKS5 constants (RFC 1928) ────────────────────────────────────────
const SOCKS_VERSION = 0x05;
const SOCKS_AUTH_NONE = 0x00;
const SOCKS_AUTH_NO_ACCEPTABLE = 0xff;
const SOCKS_CMD_CONNECT = 0x01;
const SOCKS_ATYP_IPV4 = 0x01;
const SOCKS_ATYP_DOMAIN = 0x03;
const SOCKS_ATYP_IPV6 = 0x04;
const SOCKS_REP_SUCCESS = 0x00;
const SOCKS_REP_GENERAL_FAILURE = 0x01;
const SOCKS_REP_NOT_ALLOWED = 0x02;
const SOCKS_REP_ATYP_NOT_SUPPORTED = 0x08;

// ─── Parsing helpers ───────────────────────────────────────────────────

/**
 * Parse `host:port` (or just `host`) from a CONNECT target / Host header.
 * Reverse-engineered from.
 *
 * Handles:
 * - `[::1]:443` — bracketed IPv6 + port
 * - `127.0.0.1:80` — IPv4 + port
 * - `::1` — bare IPv6 (no brackets)
 * - `example.com` — bare hostname (returns defaultPort)
 *
 * @public
 */
export function parseHostPort(raw: string, defaultPort: number): HostPort {
    // IPv6 bracketed: [::1]:443
    const bracketMatch = /^\[([^\]]+)\]:(\d+)$/.exec(raw);
    if (bracketMatch) {
        const host = bracketMatch[1] ?? raw;
        const port = Number(bracketMatch[2] ?? defaultPort);
        return { host, port };
    }
    const lastColon = raw.lastIndexOf(':');
    if (lastColon === -1) {
        return { host: raw, port: defaultPort };
    }
    const afterColon = raw.slice(lastColon + 1);
    const portNum = Number(afterColon);
    if (Number.isNaN(portNum) || portNum <= 0 || portNum > 65535) {
        // Probably IPv6 without brackets
        return { host: raw, port: defaultPort };
    }
    return { host: raw.slice(0, lastColon), port: portNum };
}

/**
 * Decide whether a connection to `host:port` should be allowed.
 * Reverse-engineered from.
 *
 * @public
 */
export async function isAllowed(
    host: string,
    port: number,
    allowedHosts: readonly string[],
    askCallback?: AskCallback,
): Promise<boolean> {
    if (hostAllowedInList(host, allowedHosts)) {
        return true;
    }
    if (askCallback) {
        return Boolean(await askCallback(host, port));
    }
    return false;
}

/** Re-export `hostAllowed` for callers that don't want to import allowlist. */
function hostAllowedInList(host: string, allowedHosts: readonly string[]): boolean {
    const lower = host.toLowerCase();
    for (const entry of allowedHosts) {
        if (entry === lower) {
            return true;
        }
        if (entry.startsWith('*.')) {
            const suffix = entry.slice(1);
            if (lower.endsWith(suffix) || lower === entry.slice(2)) {
                return true;
            }
        }
    }
    return false;
}

// ─── HTTP proxy ────────────────────────────────────────────────────────

/**
 * Create an HTTP proxy server. Supports both plain HTTP forward
 * (GET/POST/etc. with absolute URL or `Host` header) and `CONNECT` tunnels.
 * Both paths check the allowlist.
 *
 * Reverse-engineered from.
 *
 * @public
 */
export function createHttpProxy(
    allowedHosts: readonly string[],
    askCallback?: AskCallback,
): HttpServer {
    const server = createHttpServer(async (req, res) => {
        // Plain HTTP request: check host allowlist
        const hostHeader = req.headers.host ?? '';
        const { host, port } = parseHostPort(hostHeader, 80);
        const allowed = await isAllowed(host, port, allowedHosts, askCallback);
        if (!allowed) {
            res.writeHead(403, { 'Content-Type': 'text/plain' });
            res.end('Forbidden by sandbox network policy');
            return;
        }
        // Forward plain HTTP request
        const options = {
            hostname: host,
            port,
            path: req.url,
            method: req.method,
            headers: req.headers,
        };
        const proxyReq = httpRequest(options, (proxyRes) => {
            res.writeHead(proxyRes.statusCode ?? 502, proxyRes.headers);
            proxyRes.pipe(res, { end: true });
        });
        proxyReq.on('error', () => {
            if (!res.headersSent) {
                res.writeHead(502, { 'Content-Type': 'text/plain' });
            }
            res.end('Bad Gateway');
        });
        req.pipe(proxyReq, { end: true });
    });

    // CONNECT tunnel
    server.on('connect', (req, clientSocket, head) => {
        void (async () => {
            const { host, port } = parseHostPort(req.url ?? '', 443);
            const allowed = await isAllowed(host, port, allowedHosts, askCallback);
            if (!allowed) {
                clientSocket.write('HTTP/1.1 403 Forbidden\r\n\r\nForbidden by sandbox network policy');
                clientSocket.end();
                return;
            }
            const serverSocket = netConnect(port, host, () => {
                clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
                if (head.length > 0) {
                    serverSocket.write(head);
                }
                serverSocket.pipe(clientSocket);
                clientSocket.pipe(serverSocket);
            });
            serverSocket.on('error', () => {
                clientSocket.write('HTTP/1.1 502 Bad Gateway\r\n\r\nBad Gateway');
                clientSocket.end();
            });
            clientSocket.on('error', () => {
                serverSocket.destroy();
            });
        })();
    });

    return server;
}

// ─── SOCKS5 proxy ──────────────────────────────────────────────────────

function createSocksSuccessReply(): Buffer {
    return Buffer.from([
        SOCKS_VERSION,
        SOCKS_REP_SUCCESS,
        0x00,
        SOCKS_ATYP_IPV4,
        0, 0, 0, 0, // 0.0.0.0
        0, 0, // port 0
    ]);
}

function createSocksReply(rep: number): Buffer {
    return Buffer.from([
        SOCKS_VERSION,
        rep,
        0x00,
        SOCKS_ATYP_IPV4,
        0, 0, 0, 0,
        0, 0,
    ]);
}

/**
 * Parse a SOCKS5 CONNECT request. Returns the parsed {host, port, consumed}
 * on success, `null` on a malformed request (caller should send general
 * failure), or `undefined` if the buffer is too short to decide yet
 * (caller should buffer more data).
 *
 * Reverse-engineered from.
 *
 * @public
 */
export function parseSocksRequest(
    buffer: Buffer,
): { host: string; port: number; consumed: number } | null | undefined {
    if (buffer.length < 4) {
        return undefined;
    }
    const ver = buffer[0] ?? SOCKS_REP_GENERAL_FAILURE;
    const cmd = buffer[1] ?? SOCKS_REP_GENERAL_FAILURE;
    const atyp = buffer[3] ?? SOCKS_REP_ATYP_NOT_SUPPORTED;
    if (ver !== SOCKS_VERSION) {
        return null;
    }
    if (cmd !== SOCKS_CMD_CONNECT) {
        return null;
    }
    if (atyp === SOCKS_ATYP_IPV4) {
        if (buffer.length < 10) {
            return undefined;
        }
        return {
            host: `${buffer[4]}.${buffer[5]}.${buffer[6]}.${buffer[7]}`,
            port: buffer.readUInt16BE(8),
            consumed: 10,
        };
    }
    if (atyp === SOCKS_ATYP_DOMAIN) {
        if (buffer.length < 5) {
            return undefined;
        }
        const domainLen = buffer[4] ?? 0;
        if (buffer.length < 5 + domainLen + 2) {
            return undefined;
        }
        return {
            host: buffer.subarray(5, 5 + domainLen).toString('ascii'),
            port: buffer.readUInt16BE(5 + domainLen),
            consumed: 5 + domainLen + 2,
        };
    }
    if (atyp === SOCKS_ATYP_IPV6) {
        if (buffer.length < 22) {
            return undefined;
        }
        const ipv6Parts: string[] = [];
        for (let i = 0; i < 16; i += 2) {
            ipv6Parts.push(buffer.readUInt16BE(4 + i).toString(16));
        }
        return {
            host: ipv6Parts.join(':'),
            port: buffer.readUInt16BE(20),
            consumed: 22,
        };
    }
    return null;
}

function handleSocksConnect(
    context: { allowedHosts: readonly string[]; askCallback?: AskCallback; clientSocket: import('node:net').Socket },
    request: { host: string; port: number; consumed: number },
    pendingBuffer: Buffer,
): void {
    const { allowedHosts, askCallback, clientSocket } = context;
    void isAllowed(request.host, request.port, allowedHosts, askCallback)
        .then((allowed) => {
            if (!allowed) {
                clientSocket.end(createSocksReply(SOCKS_REP_NOT_ALLOWED));
                return;
            }
            const serverSocket = netConnect(request.port, request.host, () => {
                clientSocket.write(createSocksSuccessReply());
                if (pendingBuffer.length > 0) {
                    serverSocket.write(pendingBuffer);
                }
                serverSocket.pipe(clientSocket);
                clientSocket.pipe(serverSocket);
            });
            serverSocket.on('error', () => {
                clientSocket.end(createSocksReply(SOCKS_REP_GENERAL_FAILURE));
            });
            clientSocket.on('error', () => {
                serverSocket.destroy();
            });
        })
        .catch(() => {
            clientSocket.end(createSocksReply(SOCKS_REP_GENERAL_FAILURE));
        });
}

/**
 * Create a SOCKS5 proxy server. Minimal: no-auth, CONNECT only (BIND and
 * UDP_ASSOCIATE are not supported — the client receives general failure).
 *
 * Reverse-engineered from.
 *
 * @public
 */
export function createSocksProxy(
    allowedHosts: readonly string[],
    askCallback?: AskCallback,
): NetServer {
    const server = createNetServer((clientSocket) => {
        type Phase = 'greeting' | 'request';
        let phase: Phase = 'greeting';
        let buffer = Buffer.alloc(0);
        const onData = (chunk: Buffer): void => {
            buffer = Buffer.concat([buffer, chunk]);
            if (phase === 'greeting') {
                handleGreeting();
            } else if (phase === 'request') {
                handleRequest();
            }
        };
        clientSocket.on('data', onData);
        clientSocket.on('error', () => clientSocket.destroy());

        function handleGreeting(): void {
            // Minimum greeting: VER(1) + NMETHODS(1) + METHODS(>=1)
            if (buffer.length < 2) {
                return;
            }
            const ver = buffer[0] ?? SOCKS_REP_GENERAL_FAILURE;
            const nMethods = buffer[1] ?? 0;
            if (buffer.length < 2 + nMethods) {
                return;
            }
            if (ver !== SOCKS_VERSION) {
                clientSocket.end();
                return;
            }
            const methods = buffer.subarray(2, 2 + nMethods);
            buffer = buffer.subarray(2 + nMethods);
            if (methods.includes(SOCKS_AUTH_NONE)) {
                // Accept no-auth
                clientSocket.write(Buffer.from([SOCKS_VERSION, SOCKS_AUTH_NONE]));
                phase = 'request';
                if (buffer.length > 0) {
                    handleRequest();
                }
            } else {
                clientSocket.write(Buffer.from([SOCKS_VERSION, SOCKS_AUTH_NO_ACCEPTABLE]));
                clientSocket.end();
            }
        }

        function handleRequest(): void {
            const request = parseSocksRequest(buffer);
            if (typeof request === 'undefined') {
                return;
            }
            if (request === null) {
                sendReply(SOCKS_REP_GENERAL_FAILURE);
                return;
            }
            buffer = buffer.subarray(request.consumed);
            // Remove data listener now — we'll pipe after connecting
            clientSocket.removeListener('data', onData);
            handleSocksConnect({ clientSocket, allowedHosts, askCallback }, request, buffer);
        }

        function sendReply(rep: number): void {
            clientSocket.end(createSocksReply(rep));
        }
    });
    return server;
}

// ─── Public factory ────────────────────────────────────────────────────

/**
 * Create a host-proxy handle that exposes both an HTTP and a SOCKS5 server
 * (unless `httpOnly: true`) bound to `127.0.0.1`.
 *
 * Reverse-engineered from.
 *
 * @public
 */
export function createHostProxy(options: HostProxyOptions): HostProxyHandle {
    const { allowedHosts, askCallback, listenPort = 0, httpOnly = false } = options;
    const httpServer = createHttpProxy(allowedHosts, askCallback);
    const socksServer = httpOnly ? null : createSocksProxy(allowedHosts, askCallback);
    let running = false;
    let actualHttpPort = 0;
    let actualSocksPort = 0;

    return {
        get httpPort(): number {
            return actualHttpPort;
        },
        get socksPort(): number {
            return actualSocksPort;
        },
        get isRunning(): boolean {
            return running;
        },
        async start(): Promise<void> {
            if (running) {
                return;
            }
            await new Promise<void>((resolve, reject) => {
                const onError = (e: Error): void => reject(e);
                httpServer.once('error', onError);
                httpServer.listen(listenPort, '127.0.0.1', () => {
                    httpServer.removeListener('error', onError);
                    const addr = httpServer.address();
                    if (addr && typeof addr === 'object') {
                        actualHttpPort = addr.port;
                    }
                    resolve();
                });
            });
            if (socksServer) {
                await new Promise<void>((resolve, reject) => {
                    const onError = (e: Error): void => reject(e);
                    socksServer.once('error', onError);
                    socksServer.listen(listenPort, '127.0.0.1', () => {
                        socksServer.removeListener('error', onError);
                        const addr = socksServer.address();
                        if (addr && typeof addr === 'object') {
                            actualSocksPort = addr.port;
                        }
                        resolve();
                    });
                });
            }
            running = true;
        },
        async stop(): Promise<void> {
            if (!running) {
                return;
            }
            await new Promise<void>((resolve, reject) => {
                httpServer.close((err) => (err ? reject(err) : resolve()));
            });
            if (socksServer) {
                await new Promise<void>((resolve, reject) => {
                    socksServer.close((err) => (err ? reject(err) : resolve()));
                });
            }
            running = false;
            actualHttpPort = 0;
            actualSocksPort = 0;
        },
        _httpServer: httpServer,
        get _socksServer(): NetServer {
            if (!socksServer) {
                throw new Error('SOCKS5 server is not enabled (httpOnly=true)');
            }
            return socksServer;
        },
    };
}
