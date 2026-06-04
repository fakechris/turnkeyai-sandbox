/**
 * Lazy FFI factory: loads koffi + Win32 API bindings only on win32.
 *
 * Reverse-engineered from
 * `packages/sandbox-exec/src/windows-sandbox/ffi/windows-ffi-factory.ts`.
 *
 * On non-Windows hosts, {@link getWindowsFFI} throws synchronously. The
 * import of `koffi` itself is dynamic and only happens on first
 * {@link getWindowsFFI} call — so non-Windows `npm install` is fast and
 * koffi is never loaded.
 *
 * @public
 */

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

/** A loaded koffi DLL with a `.func()` method for binding. */
interface KoffiLib {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    func(name: string, returnType: any, argTypes: readonly any[]): any;
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
    const koffi = koffiModule as unknown as KoffiHandle;

    // ── Load DLLs ──────────────────────────────────────────────
    const kernel32 = koffi.load('kernel32.dll') as unknown as KoffiLib;
    const advapi32 = koffi.load('advapi32.dll') as unknown as KoffiLib;

    // ── koffi type declarations ────────────────────────────────
    // Matches Coze's createWindowsBindingTypes() exactly.
    // handle = pointer to opaque (Win32 HANDLE is void*).
    const handle = koffi.pointer(koffi.opaque());
    const pSid = koffi.pointer(koffi.opaque());
    const pAcl = koffi.pointer(koffi.opaque());
    const pSecurityDescriptor = koffi.pointer(koffi.opaque());

    const sidAndAttributes = koffi.struct('TRAE_SID_AND_ATTRIBUTES', {
        Sid: pSid,
        Attributes: 'uint32',
    });
    const trusteeW = koffi.struct('TRAE_TRUSTEE_W', {
        pMultipleTrustee: 'void *',
        MultipleTrusteeOperation: 'int',
        TrusteeForm: 'int',
        TrusteeType: 'int',
        ptstrName: pSid,
    });
    const explicitAccessW = koffi.struct('TRAE_EXPLICIT_ACCESS_W', {
        grfAccessPermissions: 'uint32',
        grfAccessMode: 'int',
        grfInheritance: 'uint32',
        Trustee: trusteeW,
    });

    const lpwstr = 'str16' as const;
    const bool = 'bool' as const;
    const dword = 'uint32' as const;
    const pVoid = 'void *' as const;
    const pHandle = koffi.out(koffi.pointer(handle));
    const pDword = koffi.out(koffi.pointer('uint32'));
    const pSidOut = koffi.out(koffi.pointer(pSid));
    const pAclOut = koffi.out(koffi.pointer(pAcl));
    const pSecurityDescriptorOut = koffi.out(koffi.pointer(pSecurityDescriptor));
    const pSidAndAttributes = koffi.pointer(sidAndAttributes);
    const pExplicitAccessW = koffi.pointer(explicitAccessW);

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const bind = (lib: KoffiLib, name: string, ret: any, args: readonly any[]): Win32Function =>
        (lib as any).func(name, ret, args);

    // ── kernel32 bindings ──────────────────────────────────────
    const getCurrentProcess = bind(kernel32, 'GetCurrentProcess', handle, []);
    const closeHandle = bind(kernel32, 'CloseHandle', bool, [handle]);
    const localFree = bind(kernel32, 'LocalFree', pVoid, [pVoid]);
    const getLastError = bind(kernel32, 'GetLastError', dword, []);
    const resumeThread = bind(kernel32, 'ResumeThread', dword, [handle]);
    const waitForSingleObject = bind(kernel32, 'WaitForSingleObject', dword, [handle, dword]);
    const getExitCodeProcess = bind(kernel32, 'GetExitCodeProcess', bool, [handle, pDword]);
    const createJobObjectW = bind(kernel32, 'CreateJobObjectW', handle, [pVoid, pVoid]);
    const setInformationJobObject = bind(kernel32, 'SetInformationJobObject', bool, [handle, 'int', pVoid, dword]);
    const assignProcessToJobObject = bind(kernel32, 'AssignProcessToJobObject', bool, [handle, handle]);

    // ── advapi32 bindings ──────────────────────────────────────
    const openProcessToken = bind(advapi32, 'OpenProcessToken', bool, [handle, dword, pHandle]);
    const createRestrictedToken = bind(advapi32, 'CreateRestrictedToken', bool, [
        handle,
        dword,
        dword,
        pSidAndAttributes,
        dword,
        pVoid,
        dword,
        pSidAndAttributes,
        pHandle,
    ]);
    const duplicateTokenEx = bind(advapi32, 'DuplicateTokenEx', bool, [
        handle,
        dword,
        pVoid,
        'int',
        'int',
        pHandle,
    ]);
    const getNamedSecurityInfoW = bind(advapi32, 'GetNamedSecurityInfoW', dword, [
        lpwstr,
        'int',
        dword,
        pSidOut,                   // owner — OUT
        pSidOut,                   // group — OUT
        pAclOut,                   // dacl — OUT
        pAclOut,                   // sacl — OUT
        pSecurityDescriptorOut,    // securityDescriptor — OUT
    ]);
    const setNamedSecurityInfoW = bind(advapi32, 'SetNamedSecurityInfoW', dword, [
        lpwstr,
        'int',
        dword,
        pSid,
        pSid,
        pAcl,
        pAcl,
    ]);
    const setEntriesInAclW = bind(advapi32, 'SetEntriesInAclW', dword, [
        dword,
        pExplicitAccessW,
        pAcl,
        pAclOut,
    ]);
    const convertStringSidToSidW = bind(advapi32, 'ConvertStringSidToSidW', bool, [lpwstr, pSidOut]);
    const freeSid = bind(advapi32, 'FreeSid', pVoid, [pSid]);
    const createProcessAsUserW = bind(advapi32, 'CreateProcessAsUserW', bool, [
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
    const logonUserW = bind(advapi32, 'LogonUserW', bool, [lpwstr, lpwstr, lpwstr, dword, dword, pHandle]);
    const createProcessWithLogonW = bind(advapi32, 'CreateProcessWithLogonW', bool, [
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
