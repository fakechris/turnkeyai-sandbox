/**
 * Windows Elevated user helpers (LogonUserW + CreateProcessWithLogonW).
 *
 * Reverse-engineered from
 * `packages/sandbox-exec/src/windows-sandbox/elevated/logon-user.ts`.
 *
 * The `windowsElevated` mode requires a one-time `sandbox setup-windows`
 * CLI that creates a dedicated local user account (Coze's `setupState`
 * stores the username + a base64'd password placeholder — Coze's
 * TODO note says real DPAPI encryption is future work).
 *
 * @public
 */

import { getWindowsFFI } from '../ffi/index.js';
import {
    CREATE_NO_WINDOW,
    CREATE_SUSPENDED,
    CREATE_UNICODE_ENVIRONMENT,
    LOGON32_LOGON_BATCH,
    LOGON32_PROVIDER_DEFAULT,
    LOGON_WITH_PROFILE,
} from '../ffi/koffi-bindings.js';
import { SandboxUnsupportedError } from '../../protocol/errors.js';
import type { StartedWindowsProcess } from '../legacy/restricted-token.js';

/** Handle size for x64 / arm64 = 8 bytes, x86 = 4 bytes. */
function handleSize(): number {
    return process.arch === 'x64' || process.arch === 'arm64' ? 8 : 4;
}

/** Read a process / thread handle from PROCESS_INFORMATION at the given byte offset. */
function readHandle(buffer: Buffer, offset: number): unknown {
    return handleSize() === 8 ? buffer.readBigUInt64LE(offset) : buffer.readUInt32LE(offset);
}

/** Build a Win32 Unicode environment block. See restricted-token.ts. */
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

/** Build a hidden-window STARTUPINFO. */
function createHiddenStartupInfo(): Buffer {
    const is64Bit = handleSize() === 8;
    const startupInfoSize = is64Bit ? 104 : 68;
    const dwFlagsOffset = is64Bit ? 60 : 44;
    const wShowWindowOffset = is64Bit ? 64 : 48;
    const startupInfo = Buffer.alloc(startupInfoSize);
    startupInfo.writeUInt32LE(startupInfoSize, 0);
    startupInfo.writeUInt32LE(1, dwFlagsOffset);
    startupInfo.writeUInt16LE(0, wShowWindowOffset);
    return startupInfo;
}

/** Logon result with cleanup. */
export interface LogonHandle {
    token: unknown;
    cleanup: () => Promise<void>;
}

/**
 * Log on as the sandbox user (created during `setup-windows`) using
 * `LogonUserW` with `LOGON32_LOGON_BATCH`. The returned token can be
 * used with `createProcessWithLogon`.
 *
 * @public
 */
export async function logonSandboxUser(
    accountName: string,
    password: string,
): Promise<LogonHandle> {
    if (process.platform !== 'win32') {
        throw new SandboxUnsupportedError('logonSandboxUser is only available on Windows');
    }
    const ffi = await getWindowsFFI();
    const tokenOut: unknown[] = [null];
    const ok = ffi.logonUserW(
        accountName,
        '.',
        password,
        LOGON32_LOGON_BATCH,
        LOGON32_PROVIDER_DEFAULT,
        tokenOut,
    );
    if (!ok) {
        const err = ffi.getLastError();
        throw new Error(`logonUserW failed for account "${accountName}" with error ${err}`);
    }
    const token = tokenOut[0];
    return {
        token,
        cleanup: async () => {
            const api = await getWindowsFFI();
            api.closeHandle(token);
        },
    };
}

// getWindowsFFI is cached + sync; await is a no-op kept for signature compat.
void Promise.resolve;

/**
 * Spawn `commandLine` as the sandbox user via `CreateProcessWithLogonW`.
 * Uses `LOGON_WITH_PROFILE` to load the user's profile (faster subsequent
 * launches + correct env). Process is `CREATE_SUSPENDED` so the caller
 * can assign it to a Job Object before `ResumeThread`.
 *
 * @public
 */
export async function createProcessWithLogon(
    accountName: string,
    password: string,
    commandLine: string,
    cwd: string,
    env: Record<string, string> | undefined,
): Promise<StartedWindowsProcess> {
    if (process.platform !== 'win32') {
        throw new SandboxUnsupportedError('createProcessWithLogon is only available on Windows');
    }
    const ffi = await getWindowsFFI();
    const envBlock = buildWindowsEnvironmentBlock(env);
    const startupInfo = createHiddenStartupInfo();
    // PROCESS_INFORMATION: hProcess(8) hThread(8) dwProcessId(4) dwThreadId(4)
    const processInfo = Buffer.alloc(24);
    const ok = ffi.createProcessWithLogonW(
        accountName,
        '.',
        password,
        LOGON_WITH_PROFILE,
        null,
        commandLine,
        CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
        envBlock,
        cwd,
        startupInfo,
        processInfo,
    );
    if (!ok) {
        const err = ffi.getLastError();
        throw new Error(`createProcessWithLogonW failed with error ${err}`);
    }
    const hSize = handleSize();
    const processHandle = readHandle(processInfo, 0);
    const threadHandle = readHandle(processInfo, hSize);
    const pid = processInfo.readUInt32LE(hSize * 2);
    return { processHandle, threadHandle, pid };
}
