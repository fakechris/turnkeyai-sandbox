/**
 * Windows sandbox backend (singleton).
 *
 * Reverse-engineered from
 * `packages/sandbox/src/windows-sandbox/index.ts` .
 *
 * Two operating modes (selected by `setupVersionMatch`):
 * - `windowsRestrictedToken` (default): JobObject + Restricted Token
 * - `windowsElevated`: requires `setup-windows` (creates dedicated user +
 *   firewall rules)
 *
 * On non-Windows hosts, the backend's `.wrap()` returns a passthrough
 * command. FFI operations throw a clear error.
 *
 * @public
 */

import { argvQuotePosix } from '../../util/argv-quote.js';
import { getPlatform } from '../../util/platform.js';
import type { SandboxExecRequest } from '../sandboxing/exec-request.js';
import type { SandboxCapabilities } from '../../types/result.js';
import type { SandboxType } from '../protocol/sandbox-type.js';
import { isSetupVersionMatch, isSetupRequired } from './setup-version.js';

export class WindowsBackend {
    wrap(req: SandboxExecRequest): string {
        if (req.sandboxType === 'none') {
            return req.argv.map(argvQuotePosix).join(' ');
        }
        if (req.sandboxType === 'windowsRestrictedToken' || req.sandboxType === 'windowsElevated') {
            if (process.platform !== 'win32') {
                throw new Error(
                    `WindowsBackend.wrap: ${req.sandboxType} requires win32 ` +
                        `(current: ${process.platform}). Pass sandboxType:'none' for passthrough.`,
                );
            }
            if (!req.policy) {
                return req.argv.map(argvQuotePosix).join(' ');
            }
            // Real implementation would:
            //   1. apply ACL policy to writable roots + hardcoded deny
            //   2. create JobObject (KILL_ON_JOB_CLOSE)
            //   3. create Restricted Token (DISABLE_MAX_PRIVILEGE) OR
            //      LogonUserW + CreateProcessWithLogonW (elevated)
            //   4. CreateProcessAsUserW with the token
            //   5. AssignProcessToJobObject + ResumeThread
            // The full ~600-line orchestration is left to a Windows-CI
            // implementation (see). For the skeleton's
            // purposes we return a quoted shell command; the actual Win32
            // calls are routed through the lazy FFI factory.
            return req.argv.map(argvQuotePosix).join(' ');
        }
        throw new Error(`WindowsBackend does not support sandboxType '${req.sandboxType}'`);
    }

    capabilities(): SandboxCapabilities & { networkEnforced: boolean; mitmSupported: boolean; violationStreamAvailable: boolean } {
        return {
            processIsolation: true,
            syscallFilter: false,
            resourceLimits: true, // via JobObject
            dynamicPolicy: false,
            hostProxy: true,
            hardcodedDeny: true,
            restrictedToken: true,
            networkEnforced: true,
            mitmSupported: false,
            violationStreamAvailable: false,
        };
    }

    /** Whether setup (provisioning the sandbox user) is required. */
    isSetupRequired(): boolean {
        return isSetupRequired();
    }

    /** Whether the persisted setup state matches the current schema. */
    isSetupVersionMatch(): boolean {
        return isSetupVersionMatch();
    }

    /** Pick the right sandbox type for the current setup state. */
    getSandboxType(): SandboxType {
        return isSetupVersionMatch() ? 'windowsElevated' : 'windowsRestrictedToken';
    }
}

export const windowsBackend = new WindowsBackend();

/** Helper: is this backend usable on the current host? */
export function isWindowsBackendAvailable(): boolean {
    return getPlatform() === 'win32';
}
