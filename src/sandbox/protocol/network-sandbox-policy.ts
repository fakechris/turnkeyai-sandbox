/**
 * Network sandbox policy.
 *
 * Reverse-engineered from
 * `packages/sandbox/src/protocol/network-sandbox-policy.ts` .
 *
 * @public
 */

export type NetworkMode = 'restricted' | 'open';

/** Port-only proxy configuration (filled in by the policy compiler). */
export interface ProxyConfig {
    /** Generic port — treated as HTTP proxy port. */
    port?: number;
    /** Explicit HTTP proxy port (takes precedence over `port`). */
    httpPort?: number;
    /** SOCKS5 proxy port. */
    socksPort?: number;
    strict?: boolean;
    [key: string]: unknown;
}

export interface NetworkSandboxPolicy {
    mode: NetworkMode;
    allowedHosts?: string[];
    proxy?: ProxyConfig;
    strict?: boolean;
}

export function isNetworkSandboxPolicy(v: unknown): v is NetworkSandboxPolicy {
    if (typeof v !== 'object' || v === null) {
        return false;
    }
    const r = v as Record<string, unknown>;
    if (r.mode !== 'restricted' && r.mode !== 'open') {
        return false;
    }
    if (
        r.allowedHosts !== undefined &&
        (!Array.isArray(r.allowedHosts) ||
            !(r.allowedHosts as unknown[]).every((x) => typeof x === 'string'))
    ) {
        return false;
    }
    if (r.proxy !== undefined && (typeof r.proxy !== 'object' || r.proxy === null)) {
        return false;
    }
    if (r.strict !== undefined && typeof r.strict !== 'boolean') {
        return false;
    }
    return true;
}
