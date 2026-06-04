import { describe, expect, it } from 'vitest';
import {
    applyProxyEnv,
    getProxyPorts,
    hasUsableProxyConfig,
} from '../../../src/sandbox/network/proxy-env.js';

describe('getProxyPorts', () => {
    it('returns empty when no proxy config', () => {
        expect(getProxyPorts({ mode: 'open' })).toEqual({});
    });

    it('returns httpPort + socksPort when both set', () => {
        expect(getProxyPorts({ mode: 'open', proxy: { httpPort: 8080, socksPort: 8081 } })).toEqual(
            { httpPort: 8080, socksPort: 8081 },
        );
    });

    it('returns only socksPort when only socksPort set', () => {
        expect(getProxyPorts({ mode: 'open', proxy: { socksPort: 8081 } })).toEqual({
            socksPort: 8081,
        });
    });

    it('falls back to generic port as httpPort', () => {
        expect(getProxyPorts({ mode: 'open', proxy: { port: 8080 } })).toEqual({
            httpPort: 8080,
        });
    });

    it('rejects non-integer port values', () => {
        expect(
            getProxyPorts({ mode: 'open', proxy: { port: 80.5 } }),
        ).toEqual({});
    });
});

describe('hasUsableProxyConfig', () => {
    it('is true if either port is set', () => {
        expect(hasUsableProxyConfig({ mode: 'open', proxy: { httpPort: 80 } })).toBe(true);
        expect(hasUsableProxyConfig({ mode: 'open', proxy: { socksPort: 80 } })).toBe(true);
    });

    it('is false when no proxy config', () => {
        expect(hasUsableProxyConfig({ mode: 'open' })).toBe(false);
    });
});

describe('applyProxyEnv', () => {
    it('returns false and mutates nothing when no proxy config', () => {
        const env: Record<string, string> = {};
        expect(applyProxyEnv(env, { mode: 'open' })).toBe(false);
        expect(env).toEqual({});
    });

    it('sets HTTP_PROXY and HTTPS_PROXY for httpPort', () => {
        const env: Record<string, string> = {};
        expect(applyProxyEnv(env, { mode: 'open', proxy: { httpPort: 51231 } })).toBe(true);
        expect(env.HTTP_PROXY).toBe('http://127.0.0.1:51231');
        expect(env.HTTPS_PROXY).toBe('http://127.0.0.1:51231');
        expect(env.http_proxy).toBe('http://127.0.0.1:51231');
        expect(env.https_proxy).toBe('http://127.0.0.1:51231');
        expect(env.NO_PROXY).toBe('127.0.0.1,localhost,::1');
        expect(env.no_proxy).toBe('127.0.0.1,localhost,::1');
    });

    it('sets ALL_PROXY for socksPort', () => {
        const env: Record<string, string> = {};
        applyProxyEnv(env, { mode: 'open', proxy: { socksPort: 51232 } });
        expect(env.ALL_PROXY).toBe('socks5://127.0.0.1:51232');
        expect(env.all_proxy).toBe('socks5://127.0.0.1:51232');
        expect(env.HTTP_PROXY).toBeUndefined();
    });
});
