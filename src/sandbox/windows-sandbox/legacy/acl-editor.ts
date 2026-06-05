/**
 * Windows ACL editor — save / mutate / revert DACLs.
 *
 * Reverse-engineered from
 * `packages/sandbox-exec/src/windows-sandbox/legacy/acl-editor.ts`.
 *
 * The session captures the original DACL of every path it touches; on
 * `revert()` it restores each one via `SetNamedSecurityInfoW`. This makes
 * ACL changes transactional — if the sandbox process fails halfway, the
 * caller can `revert()` and the host filesystem is unchanged.
 *
 * `EXPLICIT_ACCESS_W` is laid out as a plain JS object and passed to
 * `SetEntriesInAclW` as a single-element array. We rely on koffi's
 * ability to consume the object as a struct (Coze uses the same trick;
 * see Coze bundle line 40093: `const explicitAccess = { grfAccessPermissions: accessMask, ... }`)
 *
 * @public
 */

import { getWindowsFFI } from '../ffi/index.js';
import {
    DELETE_ACCESS,
    DACL_SECURITY_INFORMATION,
    DENY_ACCESS,
    FILE_GENERIC_READ,
    FILE_GENERIC_WRITE,
    GRANT_ACCESS,
    SE_FILE_OBJECT,
    SUB_CONTAINERS_AND_OBJECTS_INHERIT,
} from '../ffi/koffi-bindings.js';/** A captured DACL snapshot. */
interface DaclSnapshot {
    dacl: unknown;
    securityDescriptor: unknown;
}

/** ACL mutation verbs. */
export interface AclEditSession {
    addAllowReadAce(path: string, sid: string): Promise<void>;
    addAllowWriteAce(path: string, sid: string): Promise<void>;
    addDenyReadAce(path: string, sid: string): Promise<void>;
    addDenyWriteAce(path: string, sid: string): Promise<void>;
    revert(): Promise<void>;
}

/**
 * Create a fresh ACL edit session. The session records every path's
 * original DACL the first time it is touched; `revert()` is idempotent
 * (calling it twice is a no-op).
 *
 * @public
 */
export async function createAclEditSession(): Promise<AclEditSession> {
    const originals = new Map<string, DaclSnapshot>();
    const ffi = await getWindowsFFI();

    async function saveOriginalDacl(path: string): Promise<unknown> {
        const existing = originals.get(path);
        if (existing) {
            return existing.dacl;
        }
        const daclOut: unknown[] = [null];
        const sdOut: unknown[] = [null];
        const result = ffi.getNamedSecurityInfoW(
            path,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null,
            null,
            daclOut,
            null,
            sdOut,
        );
        if (result !== 0) {
            throw new Error(`getNamedSecurityInfoW failed for "${path}" with error ${result}`);
        }
        originals.set(path, { dacl: daclOut[0], securityDescriptor: sdOut[0] });
        return daclOut[0];
    }

    async function addAce(
        path: string,
        sid: string,
        accessMode: number,
        accessMask: number,
    ): Promise<void> {
        const oldDacl = await saveOriginalDacl(path);

        // Convert the string SID to a binary SID structure
        const sidOut: unknown[] = [null];
        const sidOk = ffi.convertStringSidToSidW(sid, sidOut);
        if (!sidOk) {
            const err = ffi.getLastError();
            throw new Error(`convertStringSidToSidW failed for "${sid}" with error ${err}`);
        }
        const pSid = sidOut[0];
        try {
            const explicitAccess = {
                grfAccessPermissions: accessMask,
                grfAccessMode: accessMode,
                grfInheritance: SUB_CONTAINERS_AND_OBJECTS_INHERIT,
                Trustee: {
                    TrusteeForm: 0,
                    TrusteeType: 0,
                    ptstrName: pSid,
                },
            };
            const newAclOut: unknown[] = [null];
            const entriesResult = ffi.setEntriesInAclW(1, explicitAccess, oldDacl, newAclOut);
            if (entriesResult !== 0) {
                throw new Error(`setEntriesInAclW failed for "${path}" with error ${entriesResult}`);
            }
            const newAcl = newAclOut[0];
            try {
                const setResult = ffi.setNamedSecurityInfoW(
                    path,
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    null,
                    null,
                    newAcl,
                    null,
                );
                if (setResult !== 0) {
                    throw new Error(
                        `setNamedSecurityInfoW failed for "${path}" with error ${setResult}`,
                    );
                }
            } finally {
                ffi.localFree(newAcl);
            }
        } finally {
            ffi.freeSid(pSid);
        }
    }

    return {
        async addAllowReadAce(path, sid) {
            await addAce(path, sid, GRANT_ACCESS, FILE_GENERIC_READ);
        },
        async addAllowWriteAce(path, sid) {
            await addAce(path, sid, GRANT_ACCESS, FILE_GENERIC_READ | FILE_GENERIC_WRITE);
        },
        async addDenyReadAce(path, sid) {
            await addAce(path, sid, DENY_ACCESS, FILE_GENERIC_READ);
        },
        async addDenyWriteAce(path, sid) {
            await addAce(
                path,
                sid,
                DENY_ACCESS,
                FILE_GENERIC_WRITE | DELETE_ACCESS,
            );
        },
        async revert() {
            for (const [path, entry] of originals) {
                const result = ffi.setNamedSecurityInfoW(
                    path,
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    null,
                    null,
                    entry.dacl,
                    null,
                );
                if (result !== 0) {
                    throw new Error(
                        `Failed to revert DACL for "${path}" with error ${result}`,
                    );
                }
                ffi.localFree(entry.securityDescriptor);
            }
            originals.clear();
        },
    };
}
