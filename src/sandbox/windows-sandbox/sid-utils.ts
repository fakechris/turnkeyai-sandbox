/**
 * SID derivation helpers.
 *
 * Reverse-engineered from
 * `packages/sandbox/src/windows-sandbox/sid-utils.ts` .
 *
 * On Windows, a sandbox setup is keyed off a per-cwd SID. We derive the SID
 * by hashing the canonicalized cwd path.
 *
 * @public
 */

import { createHash } from 'node:crypto';
import { resolve as pathResolve } from 'node:path';

/** Format a byte as two hex chars. */
function toHex(n: number): string {
    return n.toString(16).padStart(2, '0');
}

/** Convert a SHA-256 hash bytes-array to a Windows-style SID string. */
function bytesToSidString(bytes: Buffer): string {
    // Format: S-1-5-NNNNNN (we pick 5 = "NT Authority" with a stable 32-bit prefix).
    // The uses the first 4 bytes of SHA-256(cwd) as a 32-bit authority
    // sub-authority. We mirror that.
    const subAuthority =
        ((bytes[0] ?? 0) << 24) | ((bytes[1] ?? 0) << 16) | ((bytes[2] ?? 0) << 8) | (bytes[3] ?? 0);
    const sid = `S-1-5-21-${(subAuthority >>> 0).toString()}-1-${toHex(bytes[4] ?? 0)}${toHex(bytes[5] ?? 0)}`;
    return sid;
}

/**
 * Derive a deterministic per-cwd SID string.
 *
 * @public
 */
export function getSandboxSid(cwd: string = process.cwd()): string {
    const canonical = pathResolve(cwd);
    const hash = createHash('sha256').update(canonical).digest();
    return bytesToSidString(hash);
}
