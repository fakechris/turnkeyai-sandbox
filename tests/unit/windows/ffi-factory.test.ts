import { describe, expect, it } from 'vitest';
import { getWindowsFFI, resetWindowsFFICache } from '../../../src/sandbox/windows-sandbox/ffi/index.js';

describe('getWindowsFFI', () => {
    it('rejects on non-Windows hosts (current platform guard)', async () => {
        if (process.platform === 'win32') {
            // Skip: only valid on Windows
            return;
        }
        resetWindowsFFICache();
        await expect(getWindowsFFI()).rejects.toThrow(/Windows FFI requires win32/);
    });

    it('caches the bindings on repeated calls', async () => {
        if (process.platform !== 'win32') {
            return;
        }
        resetWindowsFFICache();
        const a = await getWindowsFFI();
        const b = await getWindowsFFI();
        expect(b).toBe(a);
    });
});
