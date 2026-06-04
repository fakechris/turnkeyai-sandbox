/**
 * Adapter from `SandboxHooks.onNetworkRequest` to host-proxy's `AskCallback`.
 *
 * Reverse-engineered from
 * `packages/sandbox/src/network/ask-callback.ts` .
 *
 * @public
 */

import type { AskCallback } from './host-proxy.js';

/** Network request shape passed to hooks (-style). */
export interface NetworkHookRequest {
    host: string;
    port: number;
    protocol: 'http' | 'https';
}

/** Hook contract for sandbox event subscribers. */
export interface SandboxNetworkHooks {
    onNetworkRequest?: (req: NetworkHookRequest) => Promise<boolean> | boolean;
}

/**
 * Convert a `SandboxNetworkHooks`-shaped `onNetworkRequest` into the
 * `(host, port) => Promise<boolean>` shape expected by host-proxy's
 * {@link createHostProxy}.
 *
 * Returns `undefined` when the hook is not present, which signals the proxy
 * to deny unknown hosts outright.
 *
 * @public
 */
export function createAskCallback(hooks?: SandboxNetworkHooks): AskCallback | undefined {
    if (!hooks?.onNetworkRequest) {
        return undefined;
    }
    const { onNetworkRequest } = hooks;
    return (host, port) =>
        Promise.resolve(
            onNetworkRequest({
                host,
                port,
                protocol: port === 443 ? 'https' : 'http',
            }),
        );
}
