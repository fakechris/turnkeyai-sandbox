import { describe, expect, it } from 'vitest';
import { getWindowsFFI, resetWindowsFFICache } from '../../../src/sandbox/windows-sandbox/ffi/index.js';

describe('getWindowsFFI', () => {
    it('rejects with SandboxUnsupportedError on non-Windows hosts', async () => {
        if (process.platform === 'win32') {
            // Skip: only valid on Windows
            return;
        }
        resetWindowsFFICache();
        await expect(getWindowsFFI()).rejects.toThrow(/Windows FFI is only available on Windows/);
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
