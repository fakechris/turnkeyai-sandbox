/**
 * Proxy environment-variable helpers.
 *
 * Reverse-engineered from
 * `packages/sandbox/src/network/proxy-env.ts` .
 *
 * `applyProxyEnv` mutates a passed env object to set `HTTP_PROXY`,
 * `HTTPS_PROXY`, `ALL_PROXY`, and `NO_PROXY` so that an `sandbox` /
 * `bwrap` child automatically uses the host proxy.
 *
 * @public
 */

import type { NetworkSandboxPolicy } from '../protocol/network-sandbox-policy.js';

/** Resolved port tuple for downstream tools. */
export interface ProxyPorts {
    httpPort?: number;
    socksPort?: number;
}

/**
 * Inject proxy env vars into `env` based on the policy's `network.proxy`
 * block. Returns true if any vars were set, false if no proxy config exists.
 *
 * Reverse-engineered from.
 *
 * @public
 */
export function applyProxyEnv(
    env: Record<string, string>,
    policy: NetworkSandboxPolicy,
): boolean {
    const ports = getProxyPorts(policy);
    const httpProxyUrl =
        ports.httpPort !== undefined ? `http://127.0.0.1:${ports.httpPort}` : undefined;
    const socksProxyUrl =
        ports.socksPort !== undefined ? `socks5://127.0.0.1:${ports.socksPort}` : undefined;
    if (!httpProxyUrl && !socksProxyUrl) {
        return false;
    }
    if (httpProxyUrl) {
        env.HTTP_PROXY = httpProxyUrl;
        env.HTTPS_PROXY = httpProxyUrl;
        env.http_proxy = httpProxyUrl;
        env.https_proxy = httpProxyUrl;
    }
    if (socksProxyUrl) {
        env.ALL_PROXY = socksProxyUrl;
        env.all_proxy = socksProxyUrl;
    }
    env.NO_PROXY = '127.0.0.1,localhost,::1';
    env.no_proxy = env.NO_PROXY;
    return true;
}

/**
 * Extract the configured proxy ports from a network policy.
 * Reverse-engineered from.
 *
 * @public
 */
export function getProxyPorts(policy: NetworkSandboxPolicy): ProxyPorts {
    return getProxyPortsFromConfig(policy.proxy);
}

function getProxyPortsFromConfig(
    proxyConfig: NetworkSandboxPolicy['proxy'],
): ProxyPorts {
    if (!proxyConfig) {
        return {};
    }
    // Precedence: explicit httpPort/socksPort > generic port (HTTP only)
    if (typeof proxyConfig.httpPort === 'number' && Number.isInteger(proxyConfig.httpPort)) {
        return {
            httpPort: proxyConfig.httpPort,
            socksPort:
                typeof proxyConfig.socksPort === 'number' && Number.isInteger(proxyConfig.socksPort)
                    ? proxyConfig.socksPort
                    : undefined,
        };
    }
    if (typeof proxyConfig.socksPort === 'number' && Number.isInteger(proxyConfig.socksPort)) {
        return { socksPort: proxyConfig.socksPort };
    }
    if (typeof proxyConfig.port === 'number' && Number.isInteger(proxyConfig.port)) {
        return { httpPort: proxyConfig.port };
    }
    return {};
}

/**
 * True if the policy defines any usable proxy port.
 * Reverse-engineered from.
 *
 * @public
 */
export function hasUsableProxyConfig(policy: NetworkSandboxPolicy): boolean {
    const { httpPort, socksPort } = getProxyPorts(policy);
    return httpPort !== undefined || socksPort !== undefined;
}
