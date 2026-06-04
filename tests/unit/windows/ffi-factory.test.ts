import { describe, expect, it } from 'vitest';
import { getWindowsFFI, resetWindowsFFICache } from '../../../src/sandbox/windows-sandbox/ffi/index.js';

describe('getWindowsFFI', () => {
    it('throws on non-Windows hosts (current platform guard)', () => {
        if (process.platform === 'win32') {
            // Skip: only valid on Windows
            return;
        }
        resetWindowsFFICache();
        expect(() => getWindowsFFI()).toThrow(/Windows FFI requires win32/);
    });

    it('caches the bindings on repeated calls', () => {
        if (process.platform !== 'win32') {
            return;
        }
        resetWindowsFFICache();
        const a = getWindowsFFI();
        const b = getWindowsFFI();
        expect(b).toBe(a);
    });
});
