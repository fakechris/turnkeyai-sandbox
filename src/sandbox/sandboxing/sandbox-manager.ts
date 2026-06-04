/**
 * Sandbox manager — selects backend, transforms requests, performs preflight.
 *
 * Reverse-engineered from
 * `packages/sandbox/src/sandboxing/sandbox-manager.ts` .
 *
 * @public
 */

import type { SandboxPolicy } from '../protocol/sandbox-policy.js';
import type { SandboxType } from '../protocol/sandbox-type.js';
import type { Platform } from '../../types/platform.js';
import { getPlatform } from '../../util/platform.js';
import { macosBackend } from '../macos-sandbox/index.js';
import { linuxBackend } from '../linux-sandbox/index.js';
import { windowsBackend } from '../windows-sandbox/index.js';
// Windows backend is registered lazily to avoid loading koffi on non-Windows hosts.
import type { SandboxExecRequest } from './exec-request.js';

export type { SandboxExecRequest } from './exec-request.js';

/** Preflight result (no actual spawn). */
export interface PreflightInfo {
    sandboxType: SandboxType;
    platform: Platform;
    wrappedCommand: string;
    policy: SandboxPolicy;
}

/**
 * Pick the right backend for a host platform. Falls back to `'none'` for
 * unsupported platforms (Windows will be wired up in Phase 5).
 *
 * @public
 */
export function selectSandboxType(
    platform: Platform = getPlatform(),
    policy?: SandboxPolicy,
): SandboxType {
    // Danger-full-access policy → no actual sandbox wrapping
    if (policy?.filesystem.mode === 'dangerFullAccess') {
        return 'none';
    }
    switch (platform) {
        case 'darwin':
            return 'macosSeatbelt';
        case 'linux':
            return 'linuxBubblewrap';
        case 'win32':
            return windowsBackend.getSandboxType();
    }
}

/**
 * Top-level sandbox manager. Holds the active policy, picks the backend,
 * and orchestrates preflight + run.
 *
 * Reverse-engineered from.
 *
 * @public
 */
export class SandboxManager {
    policy: SandboxPolicy;
    platform: Platform;

    constructor(policy: SandboxPolicy, platform: Platform = getPlatform()) {
        this.policy = policy;
        this.platform = platform;
    }

    /** Initial backend selection based on platform + policy. */
    selectInitial(): SandboxType {
        return selectSandboxType(this.platform, this.policy);
    }

    /**
     * Convert a raw user command + cwd into a wrapped shell command string.
     * Throws on unsupported backend.
     */
    wrap(argv: readonly string[], options: { cwd?: string; env?: Record<string, string> } = {}): string {
        const sandboxType = this.selectInitial();
        const req: SandboxExecRequest = {
            argv: [...argv],
            cwd: options.cwd,
            env: options.env,
            policy: this.policy,
            sandboxType,
        };
        if (sandboxType === 'macosSeatbelt') {
            return macosBackend.wrap(req);
        }
        if (sandboxType === 'linuxBubblewrap') {
            return linuxBackend.wrap(req);
        }
        if (
            sandboxType === 'windowsRestrictedToken' ||
            sandboxType === 'windowsElevated'
        ) {
            return windowsBackend.wrap(req);
        }
        // 'none' (passthrough)
        return req.argv.map((a) => a).join(' ');
    }

    /**
     * Synchronous preflight: returns the wrapped command and a snapshot of
     * the policy + sandbox type without actually spawning.
     */
    preflight(argv: readonly string[], options: { cwd?: string } = {}): PreflightInfo {
        const sandboxType = this.selectInitial();
        const req: SandboxExecRequest = {
            argv: [...argv],
            cwd: options.cwd ?? process.cwd(),
            policy: this.policy,
            sandboxType,
        };
        let wrappedCommand: string;
        if (sandboxType === 'macosSeatbelt') {
            wrappedCommand = macosBackend.wrap(req);
        } else if (sandboxType === 'linuxBubblewrap') {
            wrappedCommand = linuxBackend.wrap(req);
        } else if (
            sandboxType === 'windowsRestrictedToken' ||
            sandboxType === 'windowsElevated'
        ) {
            wrappedCommand = windowsBackend.wrap(req);
        } else {
            wrappedCommand = req.argv.join(' ');
        }
        return {
            sandboxType,
            platform: this.platform,
            wrappedCommand,
            policy: this.policy,
        };
    }

    /** Update the active policy (does not retroactively re-wrap). */
    updateConfig(policy: SandboxPolicy): void {
        this.policy = policy;
    }

    getPolicy(): SandboxPolicy {
        return this.policy;
    }
}
