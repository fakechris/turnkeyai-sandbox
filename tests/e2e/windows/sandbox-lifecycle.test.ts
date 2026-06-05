/**
 * E2E tests for WindowsBackend lifecycle on macOS.
 *
 * Tests the full WindowsBackend API surface (wrap, initialize, reset,
 * capabilities, getSandboxType, getSetupState) without mocking.
 * On macOS, FFI calls inside initialize() will throw — we verify the
 * error propagates correctly and reset() is still safe to call.
 */
import { describe, expect, it } from 'vitest';

import {
    WindowsBackend,
    windowsBackend,
    isWindowsBackendAvailable,
} from '../../../src/sandbox/windows-sandbox/index.js';

const isWin32 = process.platform === 'win32';
const samplePolicy = {
    filesystem: { mode: 'readOnly' as const, writableRoots: [], readableRoots: [] },
    network: { mode: 'open' as const },
};

// ── isWindowsBackendAvailable ────────────────────────────────────

describe('isWindowsBackendAvailable', () => {
    it('returns false on macOS', { skip: isWin32 }, () => {
        expect(isWindowsBackendAvailable()).toBe(false);
    });
});

// ── WindowsBackend.wrap() ────────────────────────────────────────

describe('WindowsBackend.wrap()', () => {
    it('returns Windows-quoted command for "none"', () => {
        const cmd = windowsBackend.wrap({
            sandboxType: 'none',
            argv: ['echo', 'hello world'],
        });
        expect(cmd).toBe('"echo" "hello world"');
    });

    it('returns Windows-quoted command for "windowsRestrictedToken"', () => {
        const cmd = windowsBackend.wrap({
            sandboxType: 'windowsRestrictedToken',
            argv: ['echo', 'hello'],
            policy: samplePolicy,
        });
        expect(cmd).toBe('"echo" "hello"');
    });

    it('throws for "windowsElevated" when setup state is missing', () => {
        // On macOS there's no LOCALAPPDATA, so readSetupState() returns null,
        // so isSetupVersionMatch() returns false → throws.
        expect(() =>
            windowsBackend.wrap({
                sandboxType: 'windowsElevated',
                argv: ['echo', 'hello'],
            }),
        ).toThrow(/requires setup/);
    });

    it('returns Windows-quoted command for unknown sandbox type (passthrough)', () => {
        // Coze's backend falls through to passthrough for unknown types.
        // Cast to satisfy TypeScript.
        const cmd = windowsBackend.wrap({
            sandboxType: 'macosSeatbelt' as any,
            argv: ['ls'],
        });
        expect(cmd).toBe('"ls"');
    });
});

// ── WindowsBackend.capabilities() ────────────────────────────────

describe('WindowsBackend.capabilities()', () => {
    it('returns exactly 4 fields (matching Coze shape)', () => {
        const caps = windowsBackend.capabilities();
        const keys = Object.keys(caps);
        expect(keys).toHaveLength(4);
        expect(keys).toContain('networkEnforced');
        expect(keys).toContain('readOnlySupported');
        expect(keys).toContain('mitmSupported');
        expect(keys).toContain('violationStreamAvailable');
    });

    it('returns all-false for restricted token mode (default)', () => {
        const caps = windowsBackend.capabilities();
        expect(caps.networkEnforced).toBe(false);
        expect(caps.readOnlySupported).toBe(false);
        expect(caps.mitmSupported).toBe(false);
        expect(caps.violationStreamAvailable).toBe(false);
    });

    it('returns networkEnforced=true for elevated mode', () => {
        const backend = new WindowsBackend(samplePolicy);
        // Force elevated mode
        (backend as any).sandboxType = 'windowsElevated';
        const caps = backend.capabilities();
        expect(caps.networkEnforced).toBe(true);
        expect(caps.readOnlySupported).toBe(true);
        expect(caps.mitmSupported).toBe(true);
        expect(caps.violationStreamAvailable).toBe(false);
    });
});

// ── WindowsBackend.getSandboxType() ──────────────────────────────

describe('WindowsBackend.getSandboxType()', () => {
    it('returns windowsRestrictedToken on macOS (no setup state)', () => {
        expect(windowsBackend.getSandboxType()).toBe('windowsRestrictedToken');
    });
});

// ── WindowsBackend.getSetupState() ───────────────────────────────

describe('WindowsBackend.getSetupState()', () => {
    it('returns null on macOS (no LOCALAPPDATA)', () => {
        expect(windowsBackend.getSetupState()).toBeNull();
    });
});

// ── WindowsBackend.initialize() on macOS ────────────────────────

describe('WindowsBackend.initialize() on macOS', { skip: isWin32 }, () => {
    it('throws because FFI is unavailable', async () => {
        const backend = new WindowsBackend(samplePolicy);
        await expect(backend.initialize()).rejects.toThrow();
    });
});

// ── WindowsBackend.reset() ───────────────────────────────────────

describe('WindowsBackend.reset()', () => {
    it('is safe to call without initialize()', async () => {
        const backend = new WindowsBackend();
        // Should not throw even if nothing was initialized.
        await expect(backend.reset()).resolves.toBeUndefined();
    });

    it('is safe to call twice', async () => {
        const backend = new WindowsBackend();
        await backend.reset();
        await expect(backend.reset()).resolves.toBeUndefined();
    });
});

// ── WindowsBackend constructor ───────────────────────────────────

describe('WindowsBackend constructor', () => {
    it('accepts no arguments', () => {
        const backend = new WindowsBackend();
        expect(backend.policy).toBeNull();
    });

    it('accepts a policy', () => {
        const backend = new WindowsBackend(samplePolicy);
        expect(backend.policy).toBe(samplePolicy);
    });
});
