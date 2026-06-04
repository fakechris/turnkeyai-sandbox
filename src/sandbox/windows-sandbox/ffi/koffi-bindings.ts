/**
 * Win32 FFI constants (verbatim from Coze).
 *
 * Reverse-engineered from
 * `packages/sandbox-exec/src/windows-sandbox/ffi/koffi-bindings.ts`.
 *
 * Only the constants are exported here. The actual koffi `.func()`
 * bindings are loaded lazily inside {@link getWindowsFFI} so
 * non-Windows hosts never import koffi.
 *
 * This module exports the same set of constants as the Coze
 * original (with the webpack-renamed `koffi_bindings_*` prefixes
 * stripped), plus the `ERROR_ALREADY_EXISTS` constant used by
 * setup re-runs.
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

/** Job object info classes. */
export const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9;

/** Process creation flags. */
export const CREATE_SUSPENDED = 0x00000004;
export const CREATE_UNICODE_ENVIRONMENT = 0x00000400;
export const CREATE_NO_WINDOW = 0x08000000;

/** Logon types. */
export const LOGON32_LOGON_BATCH = 4;
export const LOGON32_PROVIDER_DEFAULT = 0;
export const LOGON_WITH_PROFILE = 0x00000001;

/** SE_OBJECT_TYPE values for GetNamedSecurityInfoW. */
export const SE_FILE_OBJECT = 1;

/** SECURITY_INFORMATION bits. */
export const DACL_SECURITY_INFORMATION = 0x00000004;

/** ACE access modes. */
export const GRANT_ACCESS = 1;
export const SET_ACCESS = 2;
export const DENY_ACCESS = 3;

/** ACE inheritance flags. */
export const SUB_CONTAINERS_AND_OBJECTS_INHERIT = 0x03;

/** Token restriction flags. */
export const DISABLE_MAX_PRIVILEGE = 0x1;

/** File generic rights (used in standard ACE masks). */
export const FILE_GENERIC_READ = 0x00120089;
export const FILE_GENERIC_WRITE = 0x00120116;
export const DELETE_ACCESS = 0x00010000;

/** Wait result constants. */
export const WAIT_OBJECT_0 = 0x00000000;
export const WAIT_TIMEOUT = 0x00000102;
export const WAIT_FAILED = 0xffffffff;
export const INFINITE = 0xffffffff;

/** Startup info flags. */
export const STARTF_USESHOWWINDOW = 0x00000001;
export const SW_HIDE = 0;

/** Error code for setup re-runs against an already-provisioned user. */
export const ERROR_ALREADY_EXISTS = 183;
