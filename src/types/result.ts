import type { Platform } from './platform.js';

/**
 * Run-result classification.
 * Reverse-engineered from `packages/sandbox-policy/src/command/classifier.ts` and
 * the various `*_evaluate*` return shapes in `engine/exec-policy-manager.ts`.
 * @public
 */
export type Safety = 'safe' | 'dangerous' | 'unknown';

/**
 * Per-command approval decision recorded in the policy engine.
 * @public
 */
export type ApprovalDecision =
    | 'approved'
    | 'approved-for-session'
    | 'approved-amendment'
    | 'denied';

/**
 * Approval policy for the engine. 
 * @public
 */
export type ApprovalPolicy = 'never' | 'on-request' | 'unless-trusted';

/**
 * The kind of path access an analysed command would touch.
 * Reverse-engineered from `sandbox-policy/src/command/analyzer.ts`.
 * @public
 */
export type PathAccessKind =
    | 'read'
    | 'write'
    | 'delete'
    | 'create'
    | 'metadata'
    | 'move_source'
    | 'move_target';

/**
 * Single path access extracted from a command.
 * @public
 */
export interface PathAccess {
    path: string;
    kind: PathAccessKind;
    command: readonly string[];
}

/**
 * Single sub-command classification as produced by `classifyCommand`.
 * @public
 */
export interface CommandClassification {
    safety: Safety;
    reason: string;
}

/**
 * Result of running a sandboxed command.
 * @public
 */
export interface RunResult {
    /** Process exit code (including signal-based termination via 128+sig). */
    exitCode: number;
    /** Captured stdout, decoded as UTF-8. */
    stdout: string;
    /** Captured stderr, decoded as UTF-8. */
    stderr: string;
    /** Wall-clock time the run took in milliseconds. */
    durationMs: number;
    /** Whether the command was killed because of `timeoutMs`. */
    timedOut: boolean;
    /** Sandbox violations captured by the log-stream-watcher (macOS) or
     * reconstructed from process exit signal. Empty on success. */
    violations: readonly SandboxViolation[];
    /** Whether a hardcoded-deny path was touched. */
    hardcodedDenyOverlap: boolean;
    /** The platform backend that actually executed. */
    sandboxType: SandboxType;
    /** Original argv that was passed in. */
    argv: readonly string[];
}

/**
 * Result of a preflight (no execution, just analysis).
 * @public
 */
export interface PreflightResult {
    argv: readonly string[];
    subCommands: readonly (readonly string[])[];
    classifications: readonly CommandClassification[];
    pathAccesses: readonly PathAccess[];
    hardcodedDenyOverlap: boolean;
    estimatedViolations: readonly EstimatedViolation[];
    sandboxType: SandboxType;
    platform: Platform;
}

/**
 * A predicted potential sandbox violation surfaced by static analysis.
 * @public
 */
export interface EstimatedViolation {
    kind: PathAccessKind;
    path: string;
    reason: string;
}

/**
 * A live sandbox violation captured at runtime.
 * @public
 */
export interface SandboxViolation {
    kind: 'fileRead' | 'fileWrite' | 'network' | 'exec' | 'other';
    path?: string;
    raw: string;
    timestamp: number;
}

/**
 * The kind of sandbox backend that handles execution.
 * Reverse-engineered from `sandbox/src/protocol/sandbox-type.ts`.
 * @public
 */
export type SandboxType =
    | 'macosSeatbelt'
    | 'linuxBubblewrap'
    | 'windowsRestrictedToken'
    | 'windowsElevated'
    | 'none';

/**
 * Capabilities reported by a backend.
 * @public
 */
export interface SandboxCapabilities {
    /** Hard isolation of process tree (vs. just file+net). */
    processIsolation: boolean;
    /** Fine-grained syscall filtering. */
    syscallFilter: boolean;
    /** Time/memory resource limits. */
    resourceLimits: boolean;
    /** Hot policy reload without restart. */
    dynamicPolicy: boolean;
    /** Native host-proxy integration. */
    hostProxy: boolean;
    /** Hardcoded-deny path list applied at compile time. */
    hardcodedDeny: boolean;
    /** Restricted-token support (Windows-only really). */
    restrictedToken: boolean;
}
