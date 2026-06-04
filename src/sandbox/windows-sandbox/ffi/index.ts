/**
 * Public surface of the Windows FFI.
 * @public
 */

export * from './koffi-bindings.js';
export { getWindowsFFI, resetWindowsFFICache } from './windows-ffi-factory.js';
export type { WindowsFFI } from './windows-ffi-factory.js';
