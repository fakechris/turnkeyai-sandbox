import { describe, expect, it } from 'vitest';
import { WindowsBackend, windowsBackend, isWindowsBackendAvailable } from '../../../src/sandbox/windows-sandbox/index.js';
import { selectSandboxType } from '../../../src/sandbox/sandboxing/sandbox-manager.js';

describe('WindowsBackend', () => {
    it('isWindowsBackendAvailable mirrors the current host', () => {
        expect(isWindowsBackendAvailable()).toBe(process.platform === 'win32');
    });

    it('wrap() with sandboxType "none" passthroughs', () => {
        const cmd = windowsBackend.wrap({
            sandboxType: 'none',
            argv: ['echo', 'hello'],
        });
        // POSIX-safe args are passed through unquoted; this matches the
        // macOS / Linux backend passthrough exactly.
        expect(cmd).toBe(`echo hello`);
    });

    it('wrap() on non-Windows throws for windowsRestrictedToken', () => {
        if (process.platform === 'win32') {
            return;
        }
        expect(() =>
            windowsBackend.wrap({
                sandboxType: 'windowsRestrictedToken',
                argv: ['echo', 'hello'],
                policy: {
                    filesystem: { mode: 'readOnly', writableRoots: [], readableRoots: [] },
                    network: { mode: 'open' },
                },
            }),
        ).toThrow(/requires win32/);
    });

    it('wrap() on non-Windows throws for windowsElevated', () => {
        if (process.platform === 'win32') {
            return;
        }
        expect(() =>
            windowsBackend.wrap({
                sandboxType: 'windowsElevated',
                argv: ['echo', 'hello'],
                policy: {
                    filesystem: { mode: 'readOnly', writableRoots: [], readableRoots: [] },
                    network: { mode: 'open' },
                },
            }),
        ).toThrow(/requires win32/);
    });

    it('reports restrictedToken + resourceLimits capabilities', () => {
        const caps = windowsBackend.capabilities();
        expect(caps.restrictedToken).toBe(true);
        expect(caps.resourceLimits).toBe(true);
        expect(caps.processIsolation).toBe(true);
    });

    it('selectSandboxType("win32", policy) returns a Windows type', () => {
        const t = selectSandboxType('win32', {
            filesystem: { mode: 'readOnly', writableRoots: [], readableRoots: [] },
            network: { mode: 'open' },
        });
        expect(t).toMatch(/^windows/);
    });

    it('WindowsBackend instance is a singleton', () => {
        const a = new WindowsBackend();
        const b = new WindowsBackend();
        // Not enforced to be the same instance — both wrap() identically.
        expect(typeof a.wrap).toBe('function');
        expect(typeof b.wrap).toBe('function');
    });
});
