/**
 * Windows Job Object helpers.
 *
 * Reverse-engineered from
 * `packages/sandbox-exec/src/windows-sandbox/legacy/job-object.ts`.
 *
 * A Job Object is a kernel-level container for processes. When the Job's
 * handle is closed (or the process tree's parent exits), the OS kills all
 * member processes. We use it to guarantee that a sandbox child cannot
 * outlive the parent — even if the user kills our process tree, the
 * Windows kernel will reap all grandchildren via `KILL_ON_JOB_CLOSE`.
 *
 * The `JOBOBJECT_EXTENDED_LIMIT_INFORMATION` struct is hand-laid out via
 * a 144-byte (x64 / arm64) or 112-byte (x86) buffer because koffi
 * struct definitions would require a separate `.struct()` declaration for
 * every field — a verbose ceremony for an OS struct we only ever set one
 * field on.
 *
 * @public
 */

import { getWindowsFFI } from '../ffi/index.js';
import { JobObjectExtendedLimitInformation, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE } from '../ffi/koffi-bindings.js';

/** Total size of `JOBOBJECT_EXTENDED_LIMIT_INFORMATION` for the current arch. */
function getExtendedLimitInformationSize(): number {
    // x64 / arm64: 144 bytes; x86: 112 bytes.
    return process.arch === 'x64' || process.arch === 'arm64' ? 144 : 112;
}

/** A created Job Object with an idempotent cleanup. */
export interface JobObject {
    jobHandle: unknown;
    cleanup: () => Promise<void>;
}

/**
 * Create a Job Object configured with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`.
 *
 * Throws if `CreateJobObjectW` or `SetInformationJobObject` fails. The
 * returned object exposes a `cleanup` callback that closes the kernel
 * handle — when the handle is closed, all member processes are
 * terminated by the Windows kernel.
 *
 * @public
 */
export async function createJobObject(): Promise<JobObject> {
    const ffi = await getWindowsFFI();
    const jobHandle = ffi.createJobObjectW(null, null);
    if (!jobHandle) {
        const err = ffi.getLastError();
        throw new Error(`createJobObjectW failed with error ${err}`);
    }
    // JOBOBJECT_EXTENDED_LIMIT_INFORMATION layout (x64):
    //   BasicLimitInformation.PerProcessUserTimeLimit: LARGE_INTEGER (8B, off 0)
    //   BasicLimitInformation.PerJobUserTimeLimit:     LARGE_INTEGER (8B, off 8)
    //   BasicLimitInformation.LimitFlags:             DWORD (4B, off 16)
    //   ... remaining fields we leave zero
    const buf = Buffer.alloc(getExtendedLimitInformationSize());
    buf.writeUInt32LE(JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, 16);
    const setOk = ffi.setInformationJobObject(
        jobHandle,
        JobObjectExtendedLimitInformation,
        buf,
        buf.length,
    );
    if (!setOk) {
        const err = ffi.getLastError();
        ffi.closeHandle(jobHandle);
        throw new Error(`setInformationJobObject failed with error ${err}`);
    }
    return {
        jobHandle,
        cleanup: async () => {
            // Re-fetch FFI in case it was reset between create + cleanup.
            const api = await getWindowsFFI();
            api.closeHandle(jobHandle);
        },
    };
}

/**
 * Assign a process handle to a Job Object. The process is typically
 * created in a `CREATE_SUSPENDED` state so this call can run before
 * any user code executes.
 *
 * @public
 */
export async function assignProcessToJob(jobHandle: unknown, processHandle: unknown): Promise<void> {
    const ffi = await getWindowsFFI();
    const ok = ffi.assignProcessToJobObject(jobHandle, processHandle);
    if (!ok) {
        const err = ffi.getLastError();
        throw new Error(`assignProcessToJobObject failed with error ${err}`);
    }
}
