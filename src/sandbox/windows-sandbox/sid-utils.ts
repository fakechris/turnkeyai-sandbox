/**
 * SID derivation helpers.
 *
 * Reverse-engineered from
 * `packages/sandbox-exec/src/windows-sandbox/sid-utils.ts`.
 *
 * Two flavors of SID are produced:
 *
 * 1. **Per-cwd Capability SID** (`generateCapabilitySid`): deterministic
 *    from the cwd path. Computes a SHA-256 hash and reads four
 *    big-endian 32-bit unsigned integers as the sub-authority values.
 *    Same cwd → same SID.
 *
 * 2. **Fixed fallback SID** (`SANDBOX_FIXED_SID`): a low-privilege
 *    built-in SID used when no cwd is provided. v1 of the protocol
 *    uses this as the per-cwd key; v2+ uses the Capability SID.
 *
 * Format produced: `S-1-5-21-{sub1}-{sub2}-{sub3}-{sub4}` (4
 * sub-authorities, identical to Coze's `generateCapabilitySid` so
 * that `setup-state.json` files written by either are
 * interchangeable).
 *
 * @public
 */

import { createHash } from 'node:crypto';

/**
 * Fixed low-privilege SID used when no cwd is provided.
 * Matches Coze's `SANDBOX_FIXED_SID` (v1 of the protocol).
 */
export const SANDBOX_FIXED_SID = 'S-1-5-21-0-0-0-1000';

/**
 * Generate a deterministic Capability SID from a cwd path.
 *
 * Computes a SHA-256 hash of `cwd`, then extracts four 32-bit
 * unsigned integers to use as the SID's sub-authority values.
 *
 * Format: `S-1-5-21-{hash[0]}-{hash[1]}-{hash[2]}-{hash[3]}`
 */
export function generateCapabilitySid(cwd: string): string {
    const hash = createHash('sha256').update(cwd).digest();
    // Read four 32-bit unsigned integers from the hash (big-endian)
    const sub1 = hash.readUInt32BE(0);
    const sub2 = hash.readUInt32BE(4);
    const sub3 = hash.readUInt32BE(8);
    const sub4 = hash.readUInt32BE(12);
    return `S-1-5-21-${sub1}-${sub2}-${sub3}-${sub4}`;
}

/**
 * Get the sandbox SID for a given cwd.
 *
 * - If `cwd` is provided, returns a deterministic per-cwd Capability
 *   SID (`generateCapabilitySid`).
 * - If `cwd` is omitted, returns {@link SANDBOX_FIXED_SID} for
 *   backward compatibility.
 *
 * @public
 */
export function getSandboxSid(cwd?: string): string {
    if (cwd !== undefined) {
        return generateCapabilitySid(cwd);
    }
    return SANDBOX_FIXED_SID;
}
