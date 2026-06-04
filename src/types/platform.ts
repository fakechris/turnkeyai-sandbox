/**
 * Supported execution platforms.
 *
/*  * @public
 */
export type Platform = 'darwin' | 'linux' | 'win32';

/**
 * Internal alias for the union of host platforms supported. The runtime
 * host might not match any of these (e.g. freebsd) — in that case the platform
 * helper throws.
 * @internal
 */
export type HostPlatform = Platform;
