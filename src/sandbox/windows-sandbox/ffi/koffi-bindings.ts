/**
 * Win32 FFI constants (verbatim from).
 *
 * Reverse-engineered from
 * `packages/sandbox/src/windows-sandbox/ffi/koffi-bindings.ts` .
 *
 * Only the constants are exported here. The actual koffi `.func()` bindings
 * are loaded lazily inside {@link getWindowsFFI} so non-Windows hosts never
 * import koffi.
 *
 * @public
 */

/** Token access rights. */
export const TOKEN_DUPLICATE = 0x0002;
export const TOKEN_ASSIGN_PRIMARY = 0x0001;
export const TOKEN_QUERY = 0x0008;
export const TOKEN_ALL_ACCESS = 0x000f01ff;

/** Job object limit flags. */
export const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000;
export const JOB_OBJECT_LIMIT_BREAKAWAY_OK = 0x0800;
export const JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK = 0x00001000;

/** Job object info classes. */
export const JobObjectExtendedLimitInformation = 9;
export const JobObjectBasicProcessIdList = 3;

/** Process creation flags. */
export const CREATE_SUSPENDED = 0x00000004;
export const CREATE_UNICODE_ENVIRONMENT = 0x00000400;
export const CREATE_NO_WINDOW = 0x08000000;
export const CREATE_BREAKAWAY_FROM_JOB = 0x01000000;
export const EXTENDED_STARTUPINFO_PRESENT = 0x00080000;

/** Logon types. */
export const LOGON32_LOGON_INTERACTIVE = 2;
export const LOGON32_LOGON_NETWORK = 3;
export const LOGON32_LOGON_BATCH = 4;
export const LOGON32_LOGON_SERVICE = 5;
export const LOGON32_PROVIDER_DEFAULT = 0;
export const LOGON32_PROVIDER_WINNT50 = 3;
export const LOGON_WITH_PROFILE = 0x00000001;
export const LOGON_NETCREDENTIALS_ONLY = 0x00000002;

/** SE_OBJECT_TYPE values for GetNamedSecurityInfoW. */
export const SE_FILE_OBJECT = 1;
export const SE_KERNEL_OBJECT = 6;
export const SE_REGISTRY_KEY = 4;
export const SE_SERVICE = 16;

/** SECURITY_INFORMATION bits. */
export const OWNER_SECURITY_INFORMATION = 0x00000001;
export const GROUP_SECURITY_INFORMATION = 0x00000002;
export const DACL_SECURITY_INFORMATION = 0x00000004;
export const SACL_SECURITY_INFORMATION = 0x00000008;
export const PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000;
export const UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000;

/** ACE access modes. */
export const GRANT_ACCESS = 1;
export const SET_ACCESS = 2;
export const DENY_ACCESS = 3;
export const REVOKE_ACCESS = 4;

/** ACE inheritance flags. */
export const SUB_CONTAINERS_AND_OBJECTS_INHERIT = 0x03;
export const SUB_OBJECTS_ONLY_INHERIT = 0x01;
export const INHERIT_NO_PROPAGATE = 0x04;

/** Token restriction flags. */
export const DISABLE_MAX_PRIVILEGE = 0x1;
export const SANDBOX_INERT = 0x2;
export const LUA_TOKEN = 0x4;
export const WRITE_RESTRICTED = 0x8;

/** File generic rights (used in standard ACE masks). */
export const FILE_GENERIC_READ = 0x00120089;
export const FILE_GENERIC_WRITE = 0x00120116;
export const FILE_GENERIC_EXECUTE = 0x001200a0;
export const DELETE_ACCESS = 0x00010000;
export const FILE_READ_DATA = 0x0001;
export const FILE_WRITE_DATA = 0x0002;
export const FILE_APPEND_DATA = 0x0004;
export const FILE_READ_EA = 0x0008;
export const FILE_WRITE_EA = 0x0010;
export const FILE_EXECUTE = 0x0020;

/** Process access rights. */
export const PROCESS_ALL_ACCESS = 0x001f0fff;
export const PROCESS_CREATE_PROCESS = 0x0080;
export const PROCESS_CREATE_THREAD = 0x0002;
export const PROCESS_DUP_HANDLE = 0x0040;
export const PROCESS_QUERY_INFORMATION = 0x0400;
export const PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
export const PROCESS_TERMINATE = 0x0001;
export const PROCESS_VM_OPERATION = 0x0008;
export const PROCESS_VM_READ = 0x0010;
export const PROCESS_VM_WRITE = 0x0020;
export const PROCESS_SET_QUOTA = 0x0100;
export const PROCESS_SET_INFORMATION = 0x0200;
export const PROCESS_SUSPEND_RESUME = 0x0800;

/** Wait result constants. */
export const WAIT_OBJECT_0 = 0x00000000;
export const WAIT_TIMEOUT = 0x00000102;
export const WAIT_FAILED = 0xFFFFFFFF;
export const INFINITE = 0xFFFFFFFF;
export const STILL_ACTIVE = 259;

/** Startup info flags. */
export const STARTF_USESHOWWINDOW = 0x00000001;
export const STARTF_USESTDHANDLES = 0x00000100;
export const SW_HIDE = 0;

/** ERROR_ALREADY_EXISTS for setup re-runs. */
export const ERROR_ALREADY_EXISTS = 183;
