/**
 * Lazy FFI factory: loads koffi + Win32 API bindings only on win32.
 *
 * Reverse-engineered from
 * `packages/sandbox/src/windows-sandbox/ffi/windows-ffi-factory.ts`
 * .
 *
 * On non-Windows hosts, {@link getWindowsFFI} throws synchronously. The
 * import of `koffi` itself is dynamic and only happens on first
 * {@link getWindowsFFI} call — so non-Windows `npm install` is fast and
 * koffi is never loaded.
 *
 * @public
 */

import { createRequire } from 'node:module';
import * as koffiModule from 'koffi';

/** A single Win32 function binding. */
export type Win32Function = (...args: never[]) => unknown;

/** Subset of koffi we use. */
export interface KoffiHandle {
    load(name: string): unknown;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    func(name: string, returnType: any, argTypes: readonly any[]): any;
    opaque(): unknown;
    pointer(base?: unknown): unknown;
    struct(name: string, fields: Record<string, string | unknown>): unknown;
    out(type: unknown): unknown;
}

/** Minimal interface for the FFI bundle (what `getWindowsFFI` returns). */
export interface WindowsFFI {
    // Token
    openProcessToken(processHandle: unknown, desiredAccess: number, tokenHandle: unknown): boolean;
    getCurrentProcess(): unknown;
    createRestrictedToken(
        existingToken: unknown,
        flags: number,
        disableSidCount: number,
        sidsToDisable: unknown,
        deletePrivilegeCount: number,
        privilegesToDelete: unknown,
        restrictSidCount: number,
        sidsToRestrict: unknown,
        newToken: unknown,
    ): boolean;
    duplicateTokenEx(
        existingToken: unknown,
        desiredAccess: number,
        tokenAttributes: unknown,
        impersonationLevel: number,
        tokenType: number,
        newToken: unknown,
    ): boolean;
    // ACL
    getNamedSecurityInfoW(
        objectName: string,
        objectType: number,
        securityInfo: number,
        owner: unknown,
        group: unknown,
        dacl: unknown,
        sacl: unknown,
        securityDescriptor: unknown,
    ): number;
    setNamedSecurityInfoW(
        objectName: string,
        objectType: number,
        securityInfo: number,
        owner: unknown,
        group: unknown,
        dacl: unknown,
        sacl: unknown,
    ): number;
    setEntriesInAclW(
        countOfEntries: number,
        entries: unknown,
        oldAcl: unknown,
        newAcl: unknown,
    ): number;
    convertStringSidToSidW(stringSid: string, sid: unknown): boolean;
    freeSid(sid: unknown): unknown;
    // Process
    createProcessAsUserW(
        token: unknown,
        applicationName: string | null,
        commandLine: string,
        processAttributes: unknown,
        threadAttributes: unknown,
        inheritHandles: boolean,
        creationFlags: number,
        environment: unknown,
        currentDirectory: string,
        startupInfo: unknown,
        processInformation: unknown,
    ): boolean;
    closeHandle(handle: unknown): boolean;
    localFree(mem: unknown): unknown;
    getLastError(): number;
    resumeThread(thread: unknown): number;
    waitForSingleObject(handle: unknown, milliseconds: number): number;
    getExitCodeProcess(handle: unknown, exitCode: unknown): boolean;
    // Elevated
    logonUserW(
        username: string,
        domain: string | null,
        password: string,
        logonType: number,
        logonProvider: number,
        token: unknown,
    ): boolean;
    createProcessWithLogonW(
        username: string,
        domain: string | null,
        password: string,
        logonFlags: number,
        applicationName: string | null,
        commandLine: string,
        creationFlags: number,
        environment: unknown,
        currentDirectory: string,
        startupInfo: unknown,
        processInformation: unknown,
    ): boolean;
    // Job object
    createJobObjectW(jobAttributes: unknown, name: unknown): unknown;
    setInformationJobObject(job: unknown, infoClass: number, info: unknown, infoLength: number): boolean;
    assignProcessToJobObject(job: unknown, process: unknown): boolean;
}

let cached: WindowsFFI | undefined;

/** Lazily load the koffi bindings. Throws on non-Windows hosts. */
export function getWindowsFFI(): WindowsFFI {
    if (cached) {
        return cached;
    }
    if (process.platform !== 'win32') {
        throw new Error(
            `Windows FFI requires win32 (current platform: ${process.platform}). ` +
                `This is a known limitation — the koffi bindings are loaded lazily to ` +
                `avoid an unconditional native dependency. Run on Windows to use the FFI.`,
        );
    }
    // Dynamic require to avoid bundler static analysis pulling koffi.
    // koffi is in `dependencies` (not peerDependencies) so it is always
    // installed alongside the package.
    const koffi = koffiModule as unknown as KoffiHandle;
    const _require = createRequire(import.meta.url);

    // Bindings declaration (mirrors lines 39708–39800). On
    // non-Windows hosts, the `koffi.load(...)` calls below would throw, but
    // the platform guard above short-circuits first. The koffi handle in the
    // callback paths is a no-op stub when this module is loaded on
    // non-Windows.
    const kernel32 = koffi.load('kernel32.dll');
    const advapi32 = koffi.load('advapi32.dll');
    void _require; // marker for tree-shaking

    const lpwstr = 'str16' as const;
    const bool = 'bool' as const;
    const dword = 'uint32' as const;
    const pVoid = 'void *' as const;
    const handle = koffi.opaque();
    const pHandle = koffi.out(koffi.pointer(handle));
    const pDword = koffi.out(koffi.pointer('uint32'));

    // We bind lazily but re-cast to Win32Function for type-safety. The actual
    // call sites never inspect the return shape; they only care about success
    // (truthy return). The koffi API is dynamically typed at runtime, so we
    // cast to the function signature once and treat the result as opaque.
    // koffi's `.pointer()` and `.out()` return `unknown` at the TS level, so
    // we coerce all return/arg types to `any` here — this is the one place
    // we accept the FFI seam being untyped.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const bind = (name: string, ret: any, args: readonly any[]): Win32Function =>
        (koffi as any).func(name, ret, args);

    // Token
    const openProcessToken = bind('OpenProcessToken', bool, [handle, dword, pHandle]);
    const getCurrentProcess = bind('GetCurrentProcess', handle, []);
    const createRestrictedToken = bind('CreateRestrictedToken', bool, [
        handle,
        dword,
        dword,
        pVoid,
        dword,
        pVoid,
        dword,
        pVoid,
        pHandle,
    ]);
    const duplicateTokenEx = bind('DuplicateTokenEx', bool, [
        handle,
        dword,
        pVoid,
        'int',
        'int',
        pHandle,
    ]);
    // ACL
    const getNamedSecurityInfoW = bind('GetNamedSecurityInfoW', dword, [
        lpwstr,
        'int',
        dword,
        pVoid,
        pVoid,
        pVoid,
        pVoid,
        pVoid,
    ]);
    const setNamedSecurityInfoW = bind('SetNamedSecurityInfoW', dword, [
        lpwstr,
        'int',
        dword,
        pVoid,
        pVoid,
        pVoid,
        pVoid,
    ]);
    const setEntriesInAclW = bind('SetEntriesInAclW', dword, [dword, pVoid, pVoid, pVoid]);
    const convertStringSidToSidW = bind('ConvertStringSidToSidW', bool, [lpwstr, pVoid]);
    const freeSid = bind('FreeSid', pVoid, [pVoid]);
    // Process
    const createProcessAsUserW = bind('CreateProcessAsUserW', bool, [
        handle,
        lpwstr,
        lpwstr,
        pVoid,
        pVoid,
        bool,
        dword,
        pVoid,
        lpwstr,
        pVoid,
        pVoid,
    ]);
    const closeHandle = bind('CloseHandle', bool, [handle]);
    const localFree = bind('LocalFree', pVoid, [pVoid]);
    const getLastError = bind('GetLastError', dword, []);
    const resumeThread = bind('ResumeThread', dword, [handle]);
    const waitForSingleObject = bind('WaitForSingleObject', dword, [handle, dword]);
    const getExitCodeProcess = bind('GetExitCodeProcess', bool, [handle, pDword]);
    // Elevated
    const logonUserW = bind('LogonUserW', bool, [lpwstr, lpwstr, lpwstr, dword, dword, pHandle]);
    const createProcessWithLogonW = bind('CreateProcessWithLogonW', bool, [
        lpwstr,
        lpwstr,
        lpwstr,
        dword,
        pVoid,
        lpwstr,
        dword,
        pVoid,
        lpwstr,
        pVoid,
        pVoid,
    ]);
    // Job object
    const createJobObjectW = bind('CreateJobObjectW', handle, [pVoid, pVoid]);
    const setInformationJobObject = bind('SetInformationJobObject', bool, [handle, 'int', pVoid, dword]);
    const assignProcessToJobObject = bind('AssignProcessToJobObject', bool, [handle, handle]);

    void kernel32;
    void advapi32;

    cached = {
        openProcessToken: openProcessToken as unknown as WindowsFFI['openProcessToken'],
        getCurrentProcess: getCurrentProcess as unknown as WindowsFFI['getCurrentProcess'],
        createRestrictedToken: createRestrictedToken as unknown as WindowsFFI['createRestrictedToken'],
        duplicateTokenEx: duplicateTokenEx as unknown as WindowsFFI['duplicateTokenEx'],
        getNamedSecurityInfoW: getNamedSecurityInfoW as unknown as WindowsFFI['getNamedSecurityInfoW'],
        setNamedSecurityInfoW: setNamedSecurityInfoW as unknown as WindowsFFI['setNamedSecurityInfoW'],
        setEntriesInAclW: setEntriesInAclW as unknown as WindowsFFI['setEntriesInAclW'],
        convertStringSidToSidW: convertStringSidToSidW as unknown as WindowsFFI['convertStringSidToSidW'],
        freeSid: freeSid as unknown as WindowsFFI['freeSid'],
        createProcessAsUserW: createProcessAsUserW as unknown as WindowsFFI['createProcessAsUserW'],
        closeHandle: closeHandle as unknown as WindowsFFI['closeHandle'],
        localFree: localFree as unknown as WindowsFFI['localFree'],
        getLastError: getLastError as unknown as WindowsFFI['getLastError'],
        resumeThread: resumeThread as unknown as WindowsFFI['resumeThread'],
        waitForSingleObject: waitForSingleObject as unknown as WindowsFFI['waitForSingleObject'],
        getExitCodeProcess: getExitCodeProcess as unknown as WindowsFFI['getExitCodeProcess'],
        logonUserW: logonUserW as unknown as WindowsFFI['logonUserW'],
        createProcessWithLogonW: createProcessWithLogonW as unknown as WindowsFFI['createProcessWithLogonW'],
        createJobObjectW: createJobObjectW as unknown as WindowsFFI['createJobObjectW'],
        setInformationJobObject: setInformationJobObject as unknown as WindowsFFI['setInformationJobObject'],
        assignProcessToJobObject: assignProcessToJobObject as unknown as WindowsFFI['assignProcessToJobObject'],
    };
    return cached;
}

/** Reset the cached FFI (for tests). */
export function resetWindowsFFICache(): void {
    cached = undefined;
}
