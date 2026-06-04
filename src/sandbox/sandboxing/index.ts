/**
 * Public surface of the sandboxing layer.
 * @public
 */

export { HARDCODED_DENY_PATHS, resolveAnchors, checkHardcodedDenyOverlap, checkPathAgainstDenyList } from './hardcoded-deny.js';
export type { SandboxExecRequest } from './exec-request.js';
export { compileConfig } from './compile.js';
export {
    LINUX_MINIMAL_READABLE_ROOTS,
    LINUX_WRITABLE_SCRATCH_ROOTS,
    shouldIncludePlatformDefaults,
    getEffectiveReadableRoots,
    getEffectiveWritableRoots,
    getAnchoredHardcodedDenyPaths,
    getParentDirectories,
    isPathCoveredByRoots,
    isDirectoryLikeHardcodedDenyPath,
    dedupeResolvedPaths,
} from './filesystem-policy.js';
export { SandboxManager, selectSandboxType } from './sandbox-manager.js';
export { wrapWithSandbox } from './wrap-with-sandbox.js';
export { runInSandbox } from './run-in-sandbox.js';
export { withShellSandbox } from './shell-sandbox.js';
export type { RunInSandboxOptions } from './run-in-sandbox.js';
export type { PreflightInfo } from './sandbox-manager.js';
