/**
 * Public surface of the network layer.
 * @public
 */

export { getDangerousTlds, normalizeAllowedHosts, hostAllowed } from './allowlist.js';
export type { NormalizeResult, RejectedHost } from './allowlist.js';

export {
    parseHostPort,
    isAllowed,
    createHttpProxy,
    createSocksProxy,
    createHostProxy,
    parseSocksRequest,
} from './host-proxy.js';
export type { HostPort, AskCallback, HostProxyOptions, HostProxyHandle } from './host-proxy.js';

export { applyProxyEnv, getProxyPorts, hasUsableProxyConfig } from './proxy-env.js';
export type { ProxyPorts } from './proxy-env.js';

export { createAskCallback } from './ask-callback.js';
export type { NetworkHookRequest, SandboxNetworkHooks } from './ask-callback.js';
