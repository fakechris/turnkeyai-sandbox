/**
 * Convenience helpers for wrapping a freeform shell command in a sandbox.
 *
 * Reverse-engineered from
 * `packages/sandbox/src/sandboxing/shell-sandbox.ts` (+).
 *
 * @public
 */

import { toShellArgv } from '../../util/shell.js';
import type { Platform } from '../../types/platform.js';
import { getPlatform } from '../../util/platform.js';
import type { SandboxPolicy } from '../protocol/sandbox-policy.js';
import { runInSandbox } from './run-in-sandbox.js';

/**
 * Run a freeform shell command string in the platform sandbox. The
 * command is first wrapped via {@link toShellArgv} (mac/linux zsh/bash
 * -c, or PowerShell `-EncodedCommand` on Windows) and then handed to
 * {@link runInSandbox} for actual execution.
 *
 * @public
 */
export async function withShellSandbox(
    command: string,
    options: {
        policy: SandboxPolicy;
        cwd?: string;
        env?: Record<string, string>;
        timeoutMs?: number;
        platform?: Platform;
    },
): Promise<Awaited<ReturnType<typeof runInSandbox>>> {
    const platform = options.platform ?? getPlatform();
    const argv = toShellArgv(command, { platform });
    return runInSandbox(argv, {
        policy: options.policy,
        cwd: options.cwd,
        env: options.env,
        timeoutMs: options.timeoutMs,
        platform,
    });
}
