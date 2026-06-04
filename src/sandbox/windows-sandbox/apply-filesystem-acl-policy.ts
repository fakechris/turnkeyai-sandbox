/**
 * Apply a filesystem ACL policy on Windows.
 *
 * Reverse-engineered from
 * `packages/sandbox-exec/src/windows-sandbox/apply-filesystem-acl-policy.ts`.
 *
 * Thin orchestrator: walks the policy's `writableRoots` /
 * `readableRoots` / `readOnlySubpaths` and asks the supplied
 * {@link AclEditSession} to add/remove ACEs for each path that
 * actually exists on disk. The actual FFI work
 * (`SetEntriesInAclW` + `SetNamedSecurityInfoW`) lives in
 * `legacy/acl-editor.ts` — this file is the policy walker only.
 *
 * On non-Windows hosts this function is unreachable: the
 * `WindowsBackend.initialize()` guard at the caller throws before
 * we get here.
 *
 * @public
 */

import { existsSync } from 'node:fs';
import { join } from 'node:path';
import type { AclEditSession } from './legacy/acl-editor.js';
import type { SandboxPolicy } from '../protocol/sandbox-policy.js';

/** Public options. */
export interface ApplyAclOptions {
    cwd?: string;
    homeDir?: string;
    /** SID of the sandbox user. Required. */
    sid?: string;
}

/**
 * Apply the filesystem ACL policy described by `policy` via `session`.
 *
 * Walks:
 * - `policy.filesystem.writableRoots[*]` → `session.addAllowWriteAce`
 *   - `writableRoots[*].readOnlySubpaths[*]` → `session.addDenyWriteAce`
 * - `policy.filesystem.readableRoots[*]` (that aren't already writable)
 *   → `session.addAllowReadAce`
 *
 * Paths that don't exist on disk are silently skipped — Windows can
 * only ACL paths that are present, and we don't want setup to fail
 * when the policy mentions optional directories.
 */
export async function applyWindowsFilesystemAclPolicy(
    session: AclEditSession,
    policy: SandboxPolicy,
    options: ApplyAclOptions = {},
): Promise<void> {
    const sidOpt = options.sid;
    if (!sidOpt) {
        throw new Error('applyWindowsFilesystemAclPolicy requires options.sid');
    }
    const sid: string = sidOpt;

    async function addAclIfPathExists(
        targetPath: string,
        apply: (path: string, sid: string) => Promise<void>,
    ): Promise<void> {
        if (!existsSync(targetPath)) {
            return;
        }
        await apply(targetPath, sid);
    }

    for (const writableRoot of policy.filesystem.writableRoots) {
        await addAclIfPathExists(writableRoot.path, session.addAllowWriteAce);
        for (const subpath of writableRoot.readOnlySubpaths) {
            const readOnlyPath = join(writableRoot.path, subpath);
            await addAclIfPathExists(readOnlyPath, session.addDenyWriteAce);
        }
    }

    for (const readableRoot of policy.filesystem.readableRoots) {
        const alreadyWritable = policy.filesystem.writableRoots.some(
            (wr) => wr.path === readableRoot,
        );
        if (!alreadyWritable) {
            await addAclIfPathExists(readableRoot, session.addAllowReadAce);
        }
    }
}
