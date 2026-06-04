/**
 * Policy compilation.
 *
 * Reverse-engineered from
 * `packages/sandbox/src/sandboxing/compile.ts` .
 *
 * `compile` is the single normalization point: defaults, allowedHosts
 * normalization, and hardcoded-deny overlap detection all happen here. After
 * `compile(cfg)`, every downstream module can trust the policy shape.
 *
 * @public
 */

import { homedir } from 'node:os';
import type { SandboxConfig } from '../protocol/sandbox-config.js';
import type { SandboxPolicy } from '../protocol/sandbox-policy.js';
import { isSandboxConfig } from '../protocol/sandbox-config.js';
import { normalizeAllowedHosts } from '../network/allowlist.js';
import { checkHardcodedDenyOverlap } from './hardcoded-deny.js';

const DEFAULT_FS: SandboxPolicy['filesystem'] = {
    mode: 'readOnly',
    writableRoots: [],
    readableRoots: [],
    includePlatformDefaults: true,
};

/**
 * Compile a raw config into a validated {@link SandboxPolicy}.
 *
 * 1. Structural validation (rejects zod-equivalent invalid input).
 * 2. `allowedHosts` normalization — reject dangerous patterns.
 * 3. Hardcoded-deny overlap detection — refuse writable roots that would
 *    unlock `.ssh` / `.git` / etc.
 *
 * Does NOT do `fs.access` (existence checks belong in preflight).
 *
 * Reverse-engineered from.
 *
 * @public
 */
export function compileConfig(cfg: unknown): SandboxPolicy {
    if (!isSandboxConfig(cfg)) {
        throw new TypeError('compileConfig: input is not a valid SandboxConfig');
    }
    const parsed: SandboxConfig = cfg;

    // Fill defaults
    parsed.filesystem.includePlatformDefaults ??= DEFAULT_FS.includePlatformDefaults;
    if (parsed.filesystem.writableRoots.length === 0 && parsed.filesystem.mode === 'readOnly') {
        // OK — empty writableRoots is the readOnly default.
    }

    // allowedHosts validation
    if (parsed.network.allowedHosts && parsed.network.allowedHosts.length > 0) {
        const { normalized, rejected } = normalizeAllowedHosts(parsed.network.allowedHosts);
        if (rejected.length > 0) {
            const reasons = rejected.map((r) => `"${r.host}": ${r.reason}`).join('; ');
            throw new Error(`Invalid allowedHosts: ${reasons}`);
        }
        parsed.network.allowedHosts = normalized;
    }

    // Hardcoded-deny overlap detection
    if (parsed.filesystem.writableRoots.length > 0) {
        const homeDir = homedir();
        const cwd = process.cwd();
        const overlaps = checkHardcodedDenyOverlap(
            parsed.filesystem.writableRoots,
            homeDir,
            cwd,
        );
        if (overlaps.length > 0) {
            throw new Error(
                `Writable roots overlap with hardcoded deny paths: ${overlaps.join(', ')}`,
            );
        }
    }

    // Cross-field validation: readOnly must not have writable roots
    if (parsed.filesystem.mode === 'readOnly' && parsed.filesystem.writableRoots.length > 0) {
        throw new Error('readOnly mode cannot have writableRoots');
    }

    return parsed as SandboxPolicy;
}
