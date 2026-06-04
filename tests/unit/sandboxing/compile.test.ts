import { describe, expect, it } from 'vitest';
import { compileConfig } from '../../../src/sandbox/sandboxing/compile.js';

describe('compileConfig', () => {
    it('accepts a valid readOnly policy', () => {
        const out = compileConfig({
            filesystem: {
                mode: 'readOnly',
                writableRoots: [],
                readableRoots: ['/tmp'],
                includePlatformDefaults: true,
            },
            network: { mode: 'open' },
        });
        expect(out.filesystem.mode).toBe('readOnly');
    });

    it('fills includePlatformDefaults default', () => {
        const out = compileConfig({
            filesystem: {
                mode: 'readOnly',
                writableRoots: [],
                readableRoots: [],
            },
            network: { mode: 'open' },
        });
        expect(out.filesystem.includePlatformDefaults).toBe(true);
    });

    it('rejects readOnly + writableRoots', () => {
        expect(() =>
            compileConfig({
                filesystem: {
                    mode: 'readOnly',
                    writableRoots: [{ path: '/tmp', readOnlySubpaths: [] }],
                    readableRoots: [],
                },
                network: { mode: 'open' },
            }),
        ).toThrow(/readOnly mode cannot have writableRoots/);
    });

    it('normalizes allowedHosts (lowercases, trims)', () => {
        const out = compileConfig({
            filesystem: { mode: 'readOnly', writableRoots: [], readableRoots: [] },
            network: { mode: 'restricted', allowedHosts: ['  Example.COM  '] },
        });
        expect(out.network.allowedHosts).toEqual(['example.com']);
    });

    it('rejects dangerous allowedHosts patterns', () => {
        expect(() =>
            compileConfig({
                filesystem: { mode: 'readOnly', writableRoots: [], readableRoots: [] },
                network: { mode: 'restricted', allowedHosts: ['*.com'] },
            }),
        ).toThrow(/Invalid allowedHosts/);
    });

    it('rejects writable roots overlapping hardcoded deny paths', () => {
        const home = process.env.HOME ?? process.env.USERPROFILE ?? '/';
        expect(() =>
            compileConfig({
                filesystem: {
                    mode: 'workspaceWrite',
                    writableRoots: [{ path: home, readOnlySubpaths: [] }],
                    readableRoots: [],
                },
                network: { mode: 'open' },
            }),
        ).toThrow(/overlap with hardcoded deny/);
    });

    it('rejects structurally invalid input', () => {
        expect(() => compileConfig({ filesystem: { mode: 'no' } })).toThrow();
        expect(() => compileConfig('not a config')).toThrow();
    });
});
