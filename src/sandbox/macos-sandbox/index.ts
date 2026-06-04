/**
 * macOS sandbox backend (singleton).
 *
 * Reverse-engineered from
 * `packages/sandbox/src/macos-sandbox/index.ts` .
 *
 * Wraps a command in `sandbox -p '<sbpl>' -- <cmd>`. When `sandboxType`
 * is `'none'`, returns the command argv unchanged (passthrough).
 *
 * @public
 */

import { argvQuotePosix } from '../../util/argv-quote.js';
import { getPlatform } from '../../util/platform.js';
import type { SandboxExecRequest } from '../sandboxing/exec-request.js';
import type { SandboxCapabilities } from '../../types/result.js';
import { buildSbplProfile } from './sbpl-builder.js';

export class MacosBackend {
    wrap(req: SandboxExecRequest): string {
        if (req.sandboxType === 'none') {
            return req.argv.map(argvQuotePosix).join(' ');
        }
        if (req.sandboxType === 'macosSeatbelt') {
            if (!req.policy) {
                return req.argv.map(argvQuotePosix).join(' ');
            }
            const logTag = Buffer.from(req.argv.join(' ')).toString('base64');
            const sbpl = buildSbplProfile(req.policy, { logTag, cwd: req.cwd });
            const quotedSbpl = argvQuotePosix(sbpl);
            const quotedCmd = req.argv.map(argvQuotePosix).join(' ');
            return `sandbox-exec -p ${quotedSbpl} -- ${quotedCmd}`;
        }
        throw new Error(`MacosBackend does not support sandboxType '${req.sandboxType}'`);
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
            violationStreamAvailable: true,
        };
    }
}

export const macosBackend = new MacosBackend();

/** Helper: is this backend usable on the current host? */
export function isMacosBackendAvailable(): boolean {
    return getPlatform() === 'darwin';
}
