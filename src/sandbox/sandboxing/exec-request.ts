/**
 * Sandbox execution request — the common envelope passed to a platform
 * backend's `.wrap()` method.
 *
 * Defined as its own module (not inside sandbox-manager.ts) to avoid a
 * circular import between backends and the manager.
 *
 * @public
 */

import type { SandboxPolicy } from '../protocol/sandbox-policy.js';
import type { SandboxType } from '../protocol/sandbox-type.js';

/** A pre-spawn sandbox request. The chosen backend turns this into a
 *  shell command string via `.wrap()`. */
export interface SandboxExecRequest {
    argv: string[];
    env?: Record<string, string>;
    cwd?: string;
    policy?: SandboxPolicy;
    sandboxType: SandboxType;
}
