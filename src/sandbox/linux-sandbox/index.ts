/**
 * Linux sandbox backend (singleton).
 *
 * Reverse-engineered from
 * `packages/sandbox/src/linux-sandbox/index.ts` .
 *
 * Wraps a command in `bwrap <args...>`. When `sandboxType` is `'none'`,
 * returns the command argv unchanged (passthrough).
 *
 * @public
 */

import { argvQuotePosix } from '../../util/argv-quote.js';
import { getPlatform } from '../../util/platform.js';
import type { SandboxExecRequest } from '../sandboxing/exec-request.js';
import type { SandboxCapabilities } from '../../types/result.js';
import { buildBubblewrapArgs } from './bubblewrap-args.js';

export class LinuxBackend {
    wrap(req: SandboxExecRequest): string {
        if (req.sandboxType === 'none') {
            return req.argv.map(argvQuotePosix).join(' ');
        }
        if (req.sandboxType === 'linuxBubblewrap') {
            if (!req.policy) {
                return req.argv.map(argvQuotePosix).join(' ');
            }
            const bwrapArgs = buildBubblewrapArgs(
                { argv: req.argv, env: req.env, cwd: req.cwd },
                req.policy,
                { cwd: req.cwd },
            );
            const parts = ['bwrap', ...bwrapArgs];
            return parts.map(argvQuotePosix).join(' ');
        }
        throw new Error(`LinuxBackend does not support sandboxType '${req.sandboxType}'`);
    }

    capabilities(): SandboxCapabilities & { networkEnforced: boolean; mitmSupported: boolean; violationStreamAvailable: boolean } {
        return {
            processIsolation: true,
            syscallFilter: false,
            resourceLimits: false,
            dynamicPolicy: false,
            hostProxy: true,
            hardcodedDeny: true,
            restrictedToken: false,
            networkEnforced: true,
            mitmSupported: false,
            violationStreamAvailable: false,
        };
    }
}

export const linuxBackend = new LinuxBackend();

/** Helper: is this backend usable on the current host? */
export function isLinuxBackendAvailable(): boolean {
    return getPlatform() === 'linux';
}
