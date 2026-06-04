/**
 * Composed sandbox policy.
 *
 * Reverse-engineered from
 * `packages/sandbox/src/protocol/sandbox-policy.ts` .
 *
 * @public
 */

import type { FileSystemSandboxPolicy } from './filesystem-sandbox-policy.js';
import { isFileSystemSandboxPolicy } from './filesystem-sandbox-policy.js';
import type { NetworkSandboxPolicy } from './network-sandbox-policy.js';
import { isNetworkSandboxPolicy } from './network-sandbox-policy.js';

export interface ProcessPolicy {
    allowExec?: boolean;
    deniedExecutables?: string[];
}

export interface SandboxPolicy {
    filesystem: FileSystemSandboxPolicy;
    network: NetworkSandboxPolicy;
    process?: ProcessPolicy;
}

export function isSandboxPolicy(v: unknown): v is SandboxPolicy {
    if (typeof v !== 'object' || v === null) {
        return false;
    }
    const r = v as Record<string, unknown>;
    if (!isFileSystemSandboxPolicy(r.filesystem)) {
        return false;
    }
    if (!isNetworkSandboxPolicy(r.network)) {
        return false;
    }
    if (r.process !== undefined) {
        if (typeof r.process !== 'object' || r.process === null) {
            return false;
        }
        const p = r.process as Record<string, unknown>;
        if (p.allowExec !== undefined && typeof p.allowExec !== 'boolean') {
            return false;
        }
        if (
            p.deniedExecutables !== undefined &&
            (!Array.isArray(p.deniedExecutables) ||
                !(p.deniedExecutables as unknown[]).every((x) => typeof x === 'string'))
        ) {
            return false;
        }
    }
    return true;
}
