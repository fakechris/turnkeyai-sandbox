/**
 * Windows Restricted Token helpers.
 *
 * Reverse-engineered from
 * `packages/sandbox-exec/src/windows-sandbox/legacy/restricted-token.ts`.
 *
 * A Restricted Token is the modern equivalent of SUID-drop on Windows:
 * we open the current process's primary token, call
 * `CreateRestrictedToken` with `DISABLE_MAX_PRIVILEGE` (and optionally a
 * restricting SID), and use the returned token as the primary token of a
 * new process via `CreateProcessAsUserW`.
 *
 * The token restricts the new process to (a) no admin privileges
 * (b) optionally only the rights granted to the restricting SID. This is
 * the `windowsRestrictedToken` Coze sandbox type — works on stock
 * Windows without `sandbox setup-windows` (in contrast to the
 * `windowsElevated` mode which requires a dedicated sandbox user).
 *
 * @public
 */

import { getWindowsFFI } from '../ffi/index.js';
import {
    CREATE_NO_WINDOW,
    CREATE_SUSPENDED,
    CREATE_UNICODE_ENVIRONMENT,
    DISABLE_MAX_PRIVILEGE,
    TOKEN_ASSIGN_PRIMARY,
    TOKEN_DUPLICATE,
    TOKEN_QUERY,
} from '../ffi/koffi-bindings.js';

/** Handle size for x64 / arm64 = 8 bytes, x86 = 4 bytes. */
function handleSize(): number {
    return process.arch === 'x64' || process.arch === 'arm64' ? 8 : 4;
}

/** Read a process / thread handle from PROCESS_INFORMATION at the given byte offset. */
function readHandle(buffer: Buffer, offset: number): unknown {
    return handleSize() === 8 ? buffer.readBigUInt64LE(offset) : buffer.readUInt32LE(offset);
}

/**
 * Build a Win32 Unicode environment block from a plain env object.
 * Returns `null` for an empty object (CreateProcessAsUserW with
 * `null` means "inherit parent's env").
 */
function buildWindowsEnvironmentBlock(env: Record<string, string> | undefined): Buffer | null {
    if (!env) {
        return null;
    }
    const entries = Object.entries(env);
    if (entries.length === 0) {
        return null;
    }
    const block =
        entries
            .sort(([a], [b]) => a.localeCompare(b, 'en', { sensitivity: 'base' }))
            .map(([k, v]) => `${k}=${v}`)
            .join('\0') + '\0\0';
    return Buffer.from(block, 'utf16le');
}

/**
 * Build a hidden-window STARTUPINFO. Coze uses `SW_HIDE` to suppress
 * the console window that would otherwise flash when launching a GUI-less
 * command.
 */
function createHiddenStartupInfo(): Buffer {
    const is64Bit = handleSize() === 8;
    const startupInfoSize = is64Bit ? 104 : 68;
    const dwFlagsOffset = is64Bit ? 60 : 44;
    const wShowWindowOffset = is64Bit ? 64 : 48;
    const startupInfo = Buffer.alloc(startupInfoSize);
    startupInfo.writeUInt32LE(startupInfoSize, 0);
    startupInfo.writeUInt32LE(1, dwFlagsOffset); // STARTF_USESHOWWINDOW
    startupInfo.writeUInt16LE(0, wShowWindowOffset); // SW_HIDE
    return startupInfo;
}

/** Restricted token + cleanup. */
export interface RestrictedTokenHandle {
    token: unknown;
    cleanup: () => Promise<void>;
}

/**
 * Create a restricted token from the current process.
 *
 * The `sandboxSid` is attached as a restricting SID so the new process
 * cannot use rights not granted to that SID via the DACL policy.
 *
 * @public
 */
export async function createRestrictedToken(sandboxSid?: string): Promise<RestrictedTokenHandle> {
    const ffi = await getWindowsFFI();
    const processHandle = ffi.getCurrentProcess();
    const tokenHandleOut: unknown[] = [null];
    const desiredAccess = TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY;
    const openOk = ffi.openProcessToken(processHandle, desiredAccess, tokenHandleOut);
    if (!openOk) {
        const err = ffi.getLastError();
        throw new Error(`openProcessToken failed with error ${err}`);
    }
    const existingToken = tokenHandleOut[0];
    let binarySandboxSid: unknown = null;
    if (sandboxSid) {
        const sidOut: unknown[] = [null];
        const sidOk = ffi.convertStringSidToSidW(sandboxSid, sidOut);
        if (!sidOk) {
            ffi.closeHandle(existingToken);
            const err = ffi.getLastError();
            throw new Error(`convertStringSidToSidW failed for "${sandboxSid}" with error ${err}`);
        }
        binarySandboxSid = sidOut[0];
    }
    const restrictedTokenOut: unknown[] = [null];
    try {
        const restrictingSid =
            binarySandboxSid === null
                ? null
                : { Sid: binarySandboxSid, Attributes: 0 };
        const createOk = ffi.createRestrictedToken(
            existingToken,
            DISABLE_MAX_PRIVILEGE,
            0,
            null,
            0,
            null,
            restrictingSid ? 1 : 0,
            restrictingSid,
            restrictedTokenOut,
        );
        if (!createOk) {
            const err = ffi.getLastError();
            throw new Error(`createRestrictedToken failed with error ${err}`);
        }
    } finally {
        ffi.closeHandle(existingToken);
        if (binarySandboxSid !== null) {
            ffi.freeSid(binarySandboxSid);
        }
    }
    const restrictedToken = restrictedTokenOut[0];
    return {
        token: restrictedToken,
        cleanup: async () => {
            const api = await getWindowsFFI();
            api.closeHandle(restrictedToken);
        },
    };
}

// getWindowsFFI is cached + sync; await is a no-op kept for signature compat.
void Promise.resolve;

/** Result of a successfully started Windows process. */
export interface StartedWindowsProcess {
    processHandle: unknown;
    threadHandle: unknown;
    pid: number;
}

/**
 * Spawn `commandLine` using the supplied restricted primary token.
 * The process is created `CREATE_SUSPENDED` so the caller can assign
 * it to a Job Object and then `ResumeThread`.
 *
 * @public
 */
export async function createProcessAsRestrictedToken(
    token: unknown,
    commandLine: string,
    cwd: string,
    env: Record<string, string> | undefined,
): Promise<StartedWindowsProcess> {
    if (process.platform !== 'win32') {
        throw new Error('createProcessAsRestrictedToken is only available on Windows');
    }
    const ffi = await getWindowsFFI();
    const envBlock = buildWindowsEnvironmentBlock(env);
    const startupInfo = createHiddenStartupInfo();
    // PROCESS_INFORMATION: hProcess(8) hThread(8) dwProcessId(4) dwThreadId(4)
    const processInfo = Buffer.alloc(24);
    const ok = ffi.createProcessAsUserW(
        token,
        null,
        commandLine,
        null,
        null,
        false,
        CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
        envBlock,
        cwd,
        startupInfo,
        processInfo,
    );
    if (!ok) {
        const err = ffi.getLastError();
        throw new Error(`createProcessAsUserW failed with error ${err}`);
    }
    const hSize = handleSize();
    const processHandle = readHandle(processInfo, 0);
    const threadHandle = readHandle(processInfo, hSize);
    const pid = processInfo.readUInt32LE(hSize * 2);
    return { processHandle, threadHandle, pid };
}
