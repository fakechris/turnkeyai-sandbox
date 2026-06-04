import { describe, expect, it } from 'vitest';
import {
    buildSbplProfile,
    escapeRegex,
    sbplQuote,
} from '../../../src/sandbox/macos-sandbox/sbpl-builder.js';

describe('sbplQuote', () => {
    it('wraps simple paths in double quotes', () => {
        expect(sbplQuote('/tmp')).toBe('"/tmp"');
    });

    it('escapes embedded double quotes', () => {
        expect(sbplQuote('/foo"bar')).toBe('"/foo\\"bar"');
    });

    it('escapes backslashes', () => {
        expect(sbplQuote('C:\\foo')).toBe('"C:\\\\foo"');
    });
});

describe('escapeRegex', () => {
    it('escapes regex meta-characters', () => {
        // 's regex does not escape '/' (SBPL regex syntax treats it
        // literally in the contexts we use it). It escapes everything else
        // in the metachar set: .*+?^${}()|[]\
        expect(escapeRegex('/tmp/.git')).toBe('/tmp/\\.git');
    });

    it('does not escape alphanumerics', () => {
        expect(escapeRegex('abc123')).toBe('abc123');
    });
});

describe('buildSbplProfile', () => {
    it('starts with (deny default) for readOnly', () => {
        const sbpl = buildSbplProfile(
            {
                filesystem: {
                    mode: 'readOnly',
                    writableRoots: [],
                    readableRoots: ['/tmp'],
                },
                network: { mode: 'open' },
            },
            { homeDir: '/Users/test', cwd: '/work' },
        );
        expect(sbpl).toContain('(version 1)');
        expect(sbpl).toContain('(deny default)');
        expect(sbpl).toContain('(allow process*)');
    });

    it('expands to (allow default) for dangerFullAccess', () => {
        const sbpl = buildSbplProfile(
            {
                filesystem: {
                    mode: 'dangerFullAccess',
                    writableRoots: [],
                    readableRoots: [],
                },
                network: { mode: 'open' },
            },
            { homeDir: '/Users/test', cwd: '/work' },
        );
        expect(sbpl).toContain('(allow default)');
        expect(sbpl).not.toContain('(allow file-read* (subpath');
    });

    it('injects hardcoded deny with parent-dir deny-unlink for ~', () => {
        const sbpl = buildSbplProfile(
            {
                filesystem: {
                    mode: 'readOnly',
                    writableRoots: [],
                    readableRoots: ['/tmp'],
                },
                network: { mode: 'open' },
            },
            { homeDir: '/Users/test', cwd: '/work' },
        );
        // .ssh is anchored to /Users/test/.ssh; parent /Users/test should be guarded
        expect(sbpl).toMatch(/\(deny file-write\* \(subpath "\/Users\/test\/\.ssh"\)\)/);
        expect(sbpl).toMatch(/vnode-type DIRECTORY/);
    });

    it('uses (deny network*) for restricted without proxy', () => {
        const sbpl = buildSbplProfile(
            {
                filesystem: { mode: 'readOnly', writableRoots: [], readableRoots: [] },
                network: { mode: 'restricted' },
            },
            { homeDir: '/Users/test', cwd: '/work' },
        );
        expect(sbpl).toContain('(deny network*)');
    });

    it('allows loopback + proxy port for restricted + proxy', () => {
        const sbpl = buildSbplProfile(
            {
                filesystem: { mode: 'readOnly', writableRoots: [], readableRoots: [] },
                network: { mode: 'restricted', proxy: { httpPort: 51231 } },
            },
            { homeDir: '/Users/test', cwd: '/work' },
        );
        expect(sbpl).toContain('(allow network-bind (local ip "127.0.0.1:*"))');
        expect(sbpl).toContain('(allow network-outbound (remote ip "127.0.0.1:51231"))');
        expect(sbpl).toContain('(allow network-outbound (remote ip "::1:51231"))');
    });

    it('allows network for open mode', () => {
        const sbpl = buildSbplProfile(
            {
                filesystem: { mode: 'readOnly', writableRoots: [], readableRoots: [] },
                network: { mode: 'open' },
            },
            { homeDir: '/Users/test', cwd: '/work' },
        );
        expect(sbpl).toContain('(allow network-outbound)');
        expect(sbpl).toContain('(allow network-inbound)');
    });

    it('skips platform defaults when includePlatformDefaults is false', () => {
        const sbpl = buildSbplProfile(
            {
                filesystem: {
                    mode: 'readOnly',
                    writableRoots: [],
                    readableRoots: [],
                    includePlatformDefaults: false,
                },
                network: { mode: 'open' },
            },
            { homeDir: '/Users/test', cwd: '/work' },
        );
        expect(sbpl).not.toContain('/Library/Apple');
    });

    it('injects logTag as a comment when provided', () => {
        const sbpl = buildSbplProfile(
            {
                filesystem: { mode: 'readOnly', writableRoots: [], readableRoots: [] },
                network: { mode: 'open' },
            },
            { homeDir: '/Users/test', cwd: '/work', logTag: 'test-tag' },
        );
        expect(sbpl).toContain(';; sandbox-tag: test-tag');
    });
});
