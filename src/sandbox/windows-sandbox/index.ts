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
 * @public
 */

import { argvQuoteWindows } from '../../util/argv-quote.js';
import { getPlatform } from '../../util/platform.js';
import type { SandboxExecRequest } from '../sandboxing/exec-request.js';
import type { SandboxPolicy } from '../protocol/sandbox-policy.js';
import type { SandboxType } from '../protocol/sandbox-type.js';
import { createAclEditSession, type AclEditSession } from './legacy/acl-editor.js';
import { applyWindowsFilesystemAclPolicy } from './apply-filesystem-acl-policy.js';
import { isSetupVersionMatch, readSetupState, type SetupState } from './setup-version.js';
import { getSandboxSid } from './sid-utils.js';

/** Windows sandbox type. */
type WindowsSandboxType = 'windowsRestrictedToken' | 'windowsElevated';

/** Capabilities returned by the Windows backend. Matches Coze's shape exactly. */
export interface WindowsBackendCapabilities {
    networkEnforced: boolean;
    readOnlySupported: boolean;
    mitmSupported: boolean;
    violationStreamAvailable: boolean;
}

/**
 * WindowsBackend — owns the ACL session and (when in elevated mode) the
 * list of elevated-mode cleanups that need to run on `reset()).
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
     * Matches Coze's control flow exactly:
     * 1. `windowsElevated` → check setup state, then argvQuoteWindows
     * 2. `windowsRestrictedToken` → argvQuoteWindows (ACL protection
     *    is already set up by `initialize()`)
     * 3. Any other type (including `'none'`) → argvQuoteWindows passthrough
     */
    wrap(req: SandboxExecRequest): string {
        if (req.sandboxType === 'windowsElevated') {
            if (!isSetupVersionMatch()) {
                throw new Error(
                    'Windows Elevated backend requires setup. Run `turnkeyai-sandbox setup-windows` first.',
                );
            }
            return req.argv.map(argvQuoteWindows).join(' ');
        }
        if (req.sandboxType === 'windowsRestrictedToken') {
            return req.argv.map(argvQuoteWindows).join(' ');
        }
        // 'none' or unknown — passthrough with Windows quoting
        return req.argv.map(argvQuoteWindows).join(' ');
    }

    /**
     * Return capabilities for the active sandbox type.
     *
     * Matches Coze's shape exactly (4 fields):
     * - `windowsElevated`: network enforced, read-only supported, MITM supported
     * - `windowsRestrictedToken` / default: all false
     */
    capabilities(): WindowsBackendCapabilities {
        if (this.sandboxType === 'windowsElevated') {
            return {
                networkEnforced: true,
                readOnlySupported: true,
                mitmSupported: true,
                violationStreamAvailable: false,
            };
        }
        return {
            networkEnforced: false,
            readOnlySupported: false,
            mitmSupported: false,
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
        const effectivePolicy = policy ?? this.policy;
        if (effectivePolicy) {
            this.policy = effectivePolicy;
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
        const sid = getSandboxSid(cwd);
        const homeDir =
            process.env.HOME ?? process.env.USERPROFILE ?? 'C:\\Users\\Default';
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
}

export const windowsBackend = new WindowsBackend();

/** Helper: is this backend usable on the current host? */
export function isWindowsBackendAvailable(): boolean {
    return getPlatform() === 'win32';
}
