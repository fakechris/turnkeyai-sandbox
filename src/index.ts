/**
 * @turnkeyai/sandbox — cross-platform OS-level command sandbox.
 *
 * Public API. Each sub-path is filled in as the corresponding module lands.
 *
 * @public
 */

export { VERSION } from './version.js';

export type {
    Platform,
    HostPlatform,
    Safety,
    ApprovalDecision,
    ApprovalPolicy,
    PathAccessKind,
    PathAccess,
    CommandClassification,
    RunResult,
    PreflightResult,
    EstimatedViolation,
    SandboxViolation,
    SandboxType,
    SandboxCapabilities,
} from './types/index.js';

// Util layer (Phase 1)
export { getPlatform, tryGetPlatform } from './util/platform.js';
export { argvQuotePosix, argvQuoteWindows, argvQuoteJoinPosix, argvQuoteJoinWindows } from './util/argv-quote.js';
export { safeJsonParse, safeJsonParseOrThrow } from './util/safe-json.js';
export type { SafeJsonParseOptions } from './util/safe-json.js';
export { detectShell, toShellArgv, encodePowerShellCommand } from './util/shell.js';
export type { DetectedShell, ToShellArgvOptions } from './util/shell.js';

// Policy command layer (Phase 1)
export {
    EXECUTABLE_EXTENSION_RE,
    getCommandBasename,
    normalizeCommandName,
    getShellWrapInfo,
    isShellWrapped,
    parseCommand,
    tokenizeShellString,
    tokenizePowerShellString,
    tokenizeCmdString,
    classifyCommand,
    isSafeCommand,
    isDangerousCommand,
    extractCommandPathAccesses,
    analyzeCommand,
} from './policy/command/index.js';
export type { ShellWrapInfo } from './policy/command/parser.js';

// Policy rules layer (Phase 2)
export {
    isPatternElement,
    isDecision,
    isPrefixRule,
    isNetworkRule,
    isPolicyRule,
    isRuleFile,
    validateRuleFile,
    BANNED_RULE_PREFIXES,
    isBannedPrefix,
    appendAllowPrefixRule,
    ApprovalStore,
    argvMatchesPattern,
    evaluatePrefixRules,
    evaluateNetworkRules,
    loadRules,
    loadRuleFile,
} from './policy/rules/index.js';
export type {
    Decision,
    PatternElement,
    PrefixRule,
    NetworkRule,
    PolicyRule,
    ApprovalKey,
    StoredDecision,
    RuleDecision,
    RuleSet,
} from './policy/rules/index.js';

// Policy engine layer (Phase 2)
export { ExecPolicyManager, inferNetworkProtocol } from './policy/engine/index.js';
export type {
    EvaluationRequirement,
    ApprovalRequest,
    ProposedAmendment,
    EvaluationContext,
    NetworkRequestInfo,
    NetworkEvaluation,
    ExecPolicyManagerOptions,
} from './policy/engine/index.js';

// Network layer (Phase 3)
export {
    getDangerousTlds,
    normalizeAllowedHosts,
    hostAllowed,
    parseHostPort,
    isAllowed,
    createHttpProxy,
    createSocksProxy,
    createHostProxy,
    parseSocksRequest,
    applyProxyEnv,
    getProxyPorts,
    hasUsableProxyConfig,
    createAskCallback,
} from './sandbox/network/index.js';
export type {
    NormalizeResult,
    RejectedHost,
    HostPort,
    AskCallback,
    HostProxyOptions,
    HostProxyHandle,
    ProxyPorts,
    NetworkHookRequest,
    SandboxNetworkHooks,
} from './sandbox/network/index.js';

// Protocol layer (Phase 4)
export {
    SandboxUnsupportedError,
    isWritableRoot,
    isFileSystemSandboxPolicy,
    isNetworkSandboxPolicy,
    isSandboxPolicy,
    isSandboxConfig,
    isSandboxType,
    SANDBOX_TYPES,
    isUserCommand,
} from './sandbox/protocol/index.js';
export type {
    WritableRoot,
    FileSystemMode,
    FileSystemSandboxPolicy,
    NetworkMode,
    NetworkSandboxPolicy,
    ProxyConfig,
    ProcessPolicy,
    SandboxPolicy,
    SandboxConfig,
    UserCommand,
} from './sandbox/protocol/index.js';

// Hardcoded-deny + filesystem-policy (Phase 4)
export {
    HARDCODED_DENY_PATHS,
    resolveAnchors,
    checkHardcodedDenyOverlap,
    checkPathAgainstDenyList,
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
} from './sandbox/sandboxing/index.js';

// Sandbox core (Phase 4)
export {
    compileConfig,
    SandboxManager,
    selectSandboxType,
    wrapWithSandbox,
    runInSandbox,
    withShellSandbox,
} from './sandbox/sandboxing/index.js';
export type { RunInSandboxOptions, SandboxExecRequest, PreflightInfo } from './sandbox/sandboxing/index.js';
// Note: SandboxType re-exported from protocol/index.js (above) and via sandboxing/index.js;

// macOS sandbox (Phase 4)
export { buildSbplProfile, sbplQuote, escapeRegex, resolveRealpath } from './sandbox/macos-sandbox/sbpl-builder.js';
export { MacosBackend, macosBackend, isMacosBackendAvailable } from './sandbox/macos-sandbox/index.js';
export { MACOS_RESTRICTED_PLATFORM_DEFAULTS_SBPL } from './sandbox/macos-sandbox/restricted-platform-defaults.js';
export type { SbplBuildOptions } from './sandbox/macos-sandbox/sbpl-builder.js';

// Linux sandbox (Phase 4)
export { buildBubblewrapArgs } from './sandbox/linux-sandbox/bubblewrap-args.js';
export { LinuxBackend, linuxBackend, isLinuxBackendAvailable } from './sandbox/linux-sandbox/index.js';
export type { BubblewrapBuildOptions } from './sandbox/linux-sandbox/bubblewrap-args.js';

// Windows sandbox (Phase 5)
export {
    SETUP_VERSION,
    getSetupStatePath,
    readSetupState,
    writeSetupState,
    isSetupRequired,
    isSetupVersionMatch,
} from './sandbox/windows-sandbox/setup-version.js';
export type { SetupState } from './sandbox/windows-sandbox/setup-version.js';
export { getSandboxSid } from './sandbox/windows-sandbox/sid-utils.js';
export { applyWindowsFilesystemAclPolicy } from './sandbox/windows-sandbox/apply-filesystem-acl-policy.js';
export type { ApplyAclOptions } from './sandbox/windows-sandbox/apply-filesystem-acl-policy.js';
export {
    WindowsBackend,
    windowsBackend,
    isWindowsBackendAvailable,
} from './sandbox/windows-sandbox/index.js';
export { getWindowsFFI, resetWindowsFFICache } from './sandbox/windows-sandbox/ffi/index.js';
export type { WindowsFFI } from './sandbox/windows-sandbox/ffi/index.js';
export * from './sandbox/windows-sandbox/ffi/koffi-bindings.js';
