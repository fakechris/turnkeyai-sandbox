/**
 * Top-level `runInSandbox` — exec a sandboxed command and return the
 * captured result.
 *
 * Reverse-engineered from
 * `packages/sandbox/src/sandboxing/run-in-sandbox.ts`
 * .
 *
 * This is a focused implementation that:
 * 1. Builds the wrapped command via {@link SandboxManager.wrap}
 * 2. `spawn`s it via `node:child_process.spawn` with shell mode
 * 3. Captures stdout/stderr
 * 4. Honors `timeoutMs`
 * 5. Returns a {@link RunResult}
 *
 * Advanced features (host-proxy runtime, network setup, socat-bridge
 * lifecycle, windows backend) live in follow-up phases.
 *
 * @public
 */

import { spawn, type ChildProcess } from 'node:child_process';
import type { Platform } from '../../types/platform.js';
import { getPlatform } from '../../util/platform.js';
import type { RunResult } from '../../types/result.js';
import type { SandboxPolicy } from '../protocol/sandbox-policy.js';
import type { SandboxType } from '../protocol/sandbox-type.js';
import { SandboxManager } from './sandbox-manager.js';

/** Public options for {@link runInSandbox}. */
export interface RunInSandboxOptions {
    policy: SandboxPolicy;
    cwd?: string;
    env?: Record<string, string>;
    timeoutMs?: number;
    platform?: Platform;
    /** When true, do not actually spawn — only return the wrapped command. */
    dryRun?: boolean;
}

const DEFAULT_TIMEOUT_MS = 60_000;

/**
 * Run a command inside the platform sandbox.
 *
 * @public
 */
export async function runInSandbox(
    cmd: string | readonly string[],
    opts: RunInSandboxOptions,
): Promise<RunResult & { wrappedCommand: string; sandboxType: SandboxType }> {
    const platform = opts.platform ?? getPlatform();
    const argv = typeof cmd === 'string' ? [cmd] : cmd;
    const manager = new SandboxManager(opts.policy, platform);
    const wrappedCommand = manager.wrap(argv, { cwd: opts.cwd });
    const sandboxType = manager.selectInitial();

    if (opts.dryRun) {
        return {
            wrappedCommand,
            sandboxType,
            exitCode: 0,
            stdout: '',
            stderr: '',
            durationMs: 0,
            timedOut: false,
            violations: [],
            hardcodedDenyOverlap: false,
            argv: [...argv],
        };
    }

    const start = Date.now();
    return new Promise((resolve) => {
        const child: ChildProcess = spawn(wrappedCommand, {
            shell: true,
            cwd: opts.cwd ?? process.cwd(),
            env: { ...process.env, ...opts.env },
            stdio: ['ignore', 'pipe', 'pipe'],
        });
        let stdout = '';
        let stderr = '';
        let timedOut = false;
        child.stdout?.on('data', (c: Buffer) => (stdout += c.toString()));
        child.stderr?.on('data', (c: Buffer) => (stderr += c.toString()));
        const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
        const timer = setTimeout(() => {
            timedOut = true;
            child.kill('SIGKILL');
        }, timeoutMs);
        child.on('error', (err) => {
            clearTimeout(timer);
            resolve({
                wrappedCommand,
                sandboxType,
                exitCode: -1,
                stdout,
                stderr: stderr + `\nspawn error: ${err.message}`,
                durationMs: Date.now() - start,
                timedOut,
                violations: [],
                hardcodedDenyOverlap: false,
                argv: [...argv],
            });
        });
        child.on('exit', (code, signal) => {
            clearTimeout(timer);
            const exitCode = typeof code === 'number' ? code : signal ? 128 + 1 : 0;
            resolve({
                wrappedCommand,
                sandboxType,
                exitCode,
                stdout,
                stderr,
                durationMs: Date.now() - start,
                timedOut,
                violations: [],
                hardcodedDenyOverlap: false,
                argv: [...argv],
            });
        });
    });
}
