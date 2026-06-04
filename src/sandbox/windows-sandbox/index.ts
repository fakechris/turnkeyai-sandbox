/**
 * Windows sandbox backend.
 *
 * Reverse-engineered from
 * `packages/sandbox-exec/src/windows-sandbox/index.ts`.
 *
 * Two operating modes (selected by `setupVersionMatch`):
 * - `windowsRestrictedToken` (default): JobObject + Restricted Token
 * - `windowsElevated`: requires `setup-windows` (creates dedicated user +
 *   firewall rules)
 *
 * Lifecycle:
 *   `initialize(policy)`  — create AclEditSession + apply filesystem ACLs
 *   `wrap(req)`           — return Windows-quoted command line
 *   `reset()`             — revert all ACL changes + run elevated cleanups
 *
 * The actual restricted-token / elevated `runInSandbox` spawn happens
 * downstream of `wrap()` (in `sandbox-manager.ts`); this backend is
 * responsible for OS-level setup + cleanup only.
 *
 * On non-Windows hosts, the backend's `wrap()` throws a clear error
 * for restricted/elevated requests; `sandboxType: 'none'` is allowed
 * as a POSIX passthrough (matches the macOS / Linux backends).
 *
 * @public
 */

import { argvQuotePosix, argvQuoteWindows } from '../../util/argv-quote.js';
import { getPlatform } from '../../util/platform.js';
import type { SandboxExecRequest } from '../sandboxing/exec-request.js';
import type { SandboxCapabilities } from '../../types/result.js';
import type { SandboxPolicy } from '../protocol/sandbox-policy.js';
import type { SandboxType } from '../protocol/sandbox-type.js';
import { createAclEditSession, type AclEditSession } from './legacy/acl-editor.js';
import { applyWindowsFilesystemAclPolicy } from './apply-filesystem-acl-policy.js';
import { isSetupVersionMatch, readSetupState, type SetupState } from './setup-version.js';
import { getSandboxSid } from './sid-utils.js';

/** Windows sandbox type. */
type WindowsSandboxType = 'windowsRestrictedToken' | 'windowsElevated';

/** Capabilities of a Windows backend (static + dynamic union). */
export interface WindowsBackendCapabilities extends SandboxCapabilities {
    networkEnforced: boolean;
    mitmSupported: boolean;
    readOnlySupported: boolean;
    violationStreamAvailable: boolean;
}

/**
 * WindowsBackend — owns the ACL session and (when in elevated mode) the
 * list of elevated-mode cleanups that need to run on `reset()`.
 */
export class WindowsBackend {
    policy: SandboxPolicy | null;
    aclSession: AclEditSession | null = null;
    sandboxType: WindowsSandboxType = 'windowsRestrictedToken';
    elevatedCleanups: Array<() => Promise<void>> = [];

    constructor(policy: SandboxPolicy | null = null) {
        this.policy = policy;
    }

    /**
     * Wrap the exec request into a Windows-quoted command string.
     *
     * For `windowsRestrictedToken` / `windowsElevated`: the actual
     * restricted-token / elevated spawn is performed in
     * `runInSandbox`, not here. The command line is identical to
     * `none`, but the filesystem is already ACL-protected by
     * `initialize()`.
     *
     * For `none`: POSIX passthrough (the macOS / Linux backends
     * produce the same string for the same input).
     */
    wrap(req: SandboxExecRequest): string {
        if (req.sandboxType === 'none') {
            return req.argv.map(argvQuotePosix).join(' ');
        }
        if (
            req.sandboxType === 'windowsRestrictedToken' ||
            req.sandboxType === 'windowsElevated'
        ) {
            if (process.platform !== 'win32') {
                throw new Error(
                    `WindowsBackend.wrap: ${req.sandboxType} requires win32 ` +
                        `(current: ${process.platform}). Pass sandboxType:'none' for passthrough.`,
                );
            }
            if (req.sandboxType === 'windowsElevated' && !isSetupVersionMatch()) {
                throw new Error(
                    'Windows Elevated backend requires setup. Run `turnkeyai-sandbox setup-windows` first.',
                );
            }
            return req.argv.map(argvQuoteWindows).join(' ');
        }
        throw new Error(`WindowsBackend does not support sandboxType '${req.sandboxType}'`);
    }

    /**
     * Return capabilities for the active sandbox type.
     *
     * - `windowsElevated`: enforced network (firewall by SID), MITM
     *   proxy supported, read-only mode supported, no ETW violation
     *   stream yet.
     * - `windowsRestrictedToken` / default: all dynamic fields false.
     */
    capabilities(): WindowsBackendCapabilities {
        if (this.sandboxType === 'windowsElevated') {
            return {
                processIsolation: true,
                syscallFilter: false,
                resourceLimits: true, // via JobObject
                dynamicPolicy: false,
                hostProxy: true,
                hardcodedDeny: true,
                restrictedToken: true,
                networkEnforced: true,
                mitmSupported: true,
                readOnlySupported: true,
                violationStreamAvailable: false,
            };
        }
        return {
            processIsolation: true,
            syscallFilter: false,
            resourceLimits: true,
            dynamicPolicy: false,
            hostProxy: true,
            hardcodedDeny: true,
            restrictedToken: true,
            networkEnforced: false,
            mitmSupported: false,
            readOnlySupported: false,
            violationStreamAvailable: false,
        };
    }

    /**
     * Set up protections for the sandbox policy.
     *
     * - Detects elevated availability via `isSetupVersionMatch()`.
     * - Creates an AclEditSession (captures originals for revert).
     * - Applies the filesystem ACL policy (writableRoots / readableRoots).
     *
     * Calling `initialize()` twice replaces the prior session after
     * `reset()`. FFI calls throw on non-Windows — this is expected;
     * `initialize()` is only called on win32.
     */
    async initialize(policy: SandboxPolicy | null = null): Promise<void> {
        if (policy) {
            this.policy = policy;
        }
        if (!this.policy) {
            return;
        }

        this.sandboxType = isSetupVersionMatch()
            ? 'windowsElevated'
            : 'windowsRestrictedToken';

        const session = await createAclEditSession();
        this.aclSession = session;

        const cwd = process.cwd();
        const homeDir =
            process.env.HOME ?? process.env.USERPROFILE ?? 'C:\\Users\\Default';
        const sid = getSandboxSid(cwd);
        await applyWindowsFilesystemAclPolicy(session, this.policy, {
            cwd,
            homeDir,
            sid,
        });
    }

    /**
     * Revert all ACL changes and run any elevated-mode cleanups.
     *
     * Idempotent: calling `reset()` after the session has been
     * cleared is a no-op.
     */
    async reset(): Promise<void> {
        // Run elevated cleanups in reverse order
        for (const cleanup of this.elevatedCleanups.reverse()) {
            try {
                await cleanup();
            } catch {
                // best-effort cleanup
            }
        }
        this.elevatedCleanups = [];

        if (this.aclSession) {
            await this.aclSession.revert();
            this.aclSession = null;
        }
    }

    /** Get the currently active sandbox type. */
    getSandboxType(): SandboxType {
        return this.sandboxType;
    }

    /** Read the persisted setup state. Returns null if not set up. */
    getSetupState(): SetupState | null {
        return readSetupState();
    }

    /** True if setup-windows has never been run, or state is older than SETUP_VERSION. */
    isSetupRequired(): boolean {
        return !isSetupVersionMatch();
    }
}

export const windowsBackend = new WindowsBackend();

/** Helper: is this backend usable on the current host? */
export function isWindowsBackendAvailable(): boolean {
    return getPlatform() === 'win32';
}
