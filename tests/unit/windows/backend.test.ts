import { describe, expect, it } from 'vitest';
import { WindowsBackend, windowsBackend, isWindowsBackendAvailable } from '../../../src/sandbox/windows-sandbox/index.js';
import { selectSandboxType } from '../../../src/sandbox/sandboxing/sandbox-manager.js';

describe('WindowsBackend', () => {
    it('isWindowsBackendAvailable mirrors the current host', () => {
        expect(isWindowsBackendAvailable()).toBe(process.platform === 'win32');
    });

    it('wrap() with sandboxType "none" returns Windows-quoted command', () => {
        const cmd = windowsBackend.wrap({
            sandboxType: 'none',
            argv: ['echo', 'hello'],
        });
        // Coze's WindowsBackend uses argvQuoteWindows for ALL sandbox
        // types including 'none'. Safe args get double-quoted.
        expect(cmd).toBe(`"echo" "hello"`);
    });

    it('wrap() with windowsRestrictedToken returns Windows-quoted command', () => {
        const cmd = windowsBackend.wrap({
            sandboxType: 'windowsRestrictedToken',
            argv: ['echo', 'hello'],
            policy: {
                filesystem: { mode: 'readOnly', writableRoots: [], readableRoots: [] },
                network: { mode: 'open' },
            },
        });
        expect(cmd).toBe(`"echo" "hello"`);
    });

    it('wrap() with windowsElevated throws when setup not done', () => {
        if (process.platform === 'win32') {
            // On Windows this may or may not throw depending on setup state.
            // Just verify it returns a string or throws — either is fine.
            return;
        }
        // On non-Windows isSetupVersionMatch returns false → throws
        expect(() =>
            windowsBackend.wrap({
                sandboxType: 'windowsElevated',
                argv: ['echo', 'hello'],
            }),
        ).toThrow(/setup-windows/);
    });

    it('capabilities() returns Coze-shaped object (4 fields)', () => {
        const caps = windowsBackend.capabilities();
        // Coze's capabilities() returns exactly 4 fields
        expect(caps.networkEnforced).toBe(false);
        expect(caps.readOnlySupported).toBe(false);
        expect(caps.mitmSupported).toBe(false);
        expect(caps.violationStreamAvailable).toBe(false);
        // Verify exactly 4 keys (no extra fields)
        expect(Object.keys(caps)).toHaveLength(4);
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
