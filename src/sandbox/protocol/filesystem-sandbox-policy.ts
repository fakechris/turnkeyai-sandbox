/**
 * File-system sandbox policy.
 *
 * Reverse-engineered from
 * `packages/sandbox/src/protocol/filesystem-sandbox-policy.ts` .
 *
 * @public
 */

import type { WritableRoot } from './writable-root.js';
import { isWritableRoot } from './writable-root.js';

/** Filesystem isolation mode. */
export type FileSystemMode = 'readOnly' | 'workspaceWrite' | 'dangerFullAccess';

/** Filesystem policy shape. */
export interface FileSystemSandboxPolicy {
    mode: FileSystemMode;
    writableRoots: WritableRoot[];
    readableRoots: string[];
    /** Defaults to `true` when omitted. Ignored when `mode === 'dangerFullAccess'`. */
    includePlatformDefaults?: boolean;
}

/** Type-guard for {@link FileSystemSandboxPolicy}. */
export function isFileSystemSandboxPolicy(v: unknown): v is FileSystemSandboxPolicy {
    if (typeof v !== 'object' || v === null) {
        return false;
    }
    const r = v as Record<string, unknown>;
    if (r.mode !== 'readOnly' && r.mode !== 'workspaceWrite' && r.mode !== 'dangerFullAccess') {
        return false;
    }
    if (!Array.isArray(r.writableRoots) || !(r.writableRoots as unknown[]).every(isWritableRoot)) {
        return false;
    }
    if (
        !Array.isArray(r.readableRoots) ||
        !(r.readableRoots as unknown[]).every((x) => typeof x === 'string')
    ) {
        return false;
    }
    if (
        r.includePlatformDefaults !== undefined &&
        typeof r.includePlatformDefaults !== 'boolean'
    ) {
        return false;
    }
    return true;
}

// Re-export for convenience
export type { WritableRoot } from './writable-root.js';
