import { describe, expect, it } from 'vitest';
import { createAskCallback } from '../../../src/sandbox/network/ask-callback.js';

describe('createAskCallback', () => {
    it('returns undefined when no hook is provided', () => {
        expect(createAskCallback()).toBeUndefined();
        expect(createAskCallback({})).toBeUndefined();
    });

    it('adapts hook result for allow', async () => {
        const cb = createAskCallback({ onNetworkRequest: async () => true });
        expect(await cb!('example.com', 443)).toBe(true);
    });

    it('adapts hook result for deny', async () => {
        const cb = createAskCallback({ onNetworkRequest: async () => false });
        expect(await cb!('example.com', 443)).toBe(false);
    });

    it('infers https from port 443', async () => {
        let captured: { host: string; port: number; protocol: 'http' | 'https' } | undefined;
        const cb = createAskCallback({
            onNetworkRequest: async (req) => {
                captured = req;
                return true;
            },
        });
        await cb!('example.com', 443);
        expect(captured?.protocol).toBe('https');
    });

    it('infers http from other ports', async () => {
        let captured: { host: string; port: number; protocol: 'http' | 'https' } | undefined;
        const cb = createAskCallback({
            onNetworkRequest: async (req) => {
                captured = req;
                return true;
            },
        });
        await cb!('example.com', 8080);
        expect(captured?.protocol).toBe('http');
    });

    it('handles sync hook returns', async () => {
        const cb = createAskCallback({ onNetworkRequest: () => false });
        expect(await cb!('example.com', 80)).toBe(false);
    });
});
