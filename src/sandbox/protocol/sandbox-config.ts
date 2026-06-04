/**
 * Top-level sandbox config schema.
 *
 * Reverse-engineered from
 * `packages/sandbox/src/protocol/sandbox-config.ts` .
 *
 * In the config type aliases the policy type (same shape). We mirror
 * that, with a distinct name so consumers can choose to type a config object
 * separately from a fully-compiled policy.
 *
 * @public
 */

import type { SandboxPolicy } from './sandbox-policy.js';
import { isSandboxPolicy } from './sandbox-policy.js';

export type SandboxConfig = SandboxPolicy;

export function isSandboxConfig(v: unknown): v is SandboxConfig {
    return isSandboxPolicy(v);
}
