/**
 * Public surface of the protocol layer.
 * @public
 */

export { SandboxUnsupportedError } from './errors.js';

export { isWritableRoot } from './writable-root.js';
export type { WritableRoot } from './writable-root.js';

export { isFileSystemSandboxPolicy } from './filesystem-sandbox-policy.js';
export type { FileSystemMode, FileSystemSandboxPolicy } from './filesystem-sandbox-policy.js';

export { isNetworkSandboxPolicy } from './network-sandbox-policy.js';
export type { NetworkMode, NetworkSandboxPolicy, ProxyConfig } from './network-sandbox-policy.js';

export { isSandboxPolicy } from './sandbox-policy.js';
export type { ProcessPolicy, SandboxPolicy } from './sandbox-policy.js';

export { isSandboxConfig } from './sandbox-config.js';
export type { SandboxConfig } from './sandbox-config.js';

export { isSandboxType, SANDBOX_TYPES } from './sandbox-type.js';
export type { SandboxType } from './sandbox-type.js';

export { isUserCommand } from './user-command.js';
export type { UserCommand } from './user-command.js';
