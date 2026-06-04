import type { Platform } from '../types/platform.js';

/**
 * Resolve the host platform to one of the three platforms.
 *
 * Reverse-engineered from `packages/sandbox/src/util/platform.ts` (
 * bundle line 42004). Throws if the host is something exotic (e.g. freebsd,
 * illumos) — call sites should catch and fall back to a sensible default.
 *
 * @public
 */
export function getPlatform(): Platform {
    const p = process.platform;
    switch (p) {
        case 'darwin':
        case 'linux':
        case 'win32':
            return p;
        default:
            throw new Error(
                `Unsupported platform: ${p}. Only darwin, linux, and win32 are supported.`,
            );
    }
}

/**
 * Try to resolve the host platform, returning `null` on unsupported.
 * @public
 */
export function tryGetPlatform(): Platform | null {
    try {
        return getPlatform();
    } catch {
        return null;
    }
}
