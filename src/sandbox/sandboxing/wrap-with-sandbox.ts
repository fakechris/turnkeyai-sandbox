/**
 * Thin wrapper: take a user command, return a wrapped shell string.
 *
 * Reverse-engineered from
 * `packages/sandbox/src/sandboxing/wrap-with-sandbox.ts` .
 *
 * @public
 */

import type { Platform } from '../../types/platform.js';
import { getPlatform } from '../../util/platform.js';
import type { SandboxPolicy } from '../protocol/sandbox-policy.js';
import { SandboxManager } from './sandbox-manager.js';

/**
 * Wrap a user command with the appropriate platform sandbox.
 *
 * @public
 */
export function wrapWithSandbox(
    cmd: string | readonly string[],
    opts: {
        policy: SandboxPolicy;
        platform?: Platform;
        cwd?: string;
    },
): string {
    const argv = typeof cmd === 'string' ? [cmd] : cmd;
    const platform = opts.platform ?? getPlatform();
    const manager = new SandboxManager(opts.policy, platform);
    return manager.wrap(argv, { cwd: opts.cwd });
}
