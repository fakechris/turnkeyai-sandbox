/**
 * ExecPolicyManager — the policy-engine state machine.
 *
 * Reverse-engineered from
 * `packages/sandbox-policy/src/engine/exec-policy-manager.ts`
 * .
 *
 * Public surface:
 * - `loadRules()` — read rules from a config dir
 * - `evaluate(argv, context)` — return the strongest requirement for a command
 * - `evaluateNetwork(host, port, protocol, context)` — same for network
 * - `createHooks(context, opts)` — wire into a sandbox's approval callbacks
 * - `recordDecision()` / `appendRule()` — persist user decisions
 *
 * @public
 */

import type { ApprovalDecision, ApprovalPolicy } from '../../types/result.js';
import { parseCommand } from '../command/parser.js';
import { classifyCommand } from '../command/classifier.js';
import {
    type PolicyRule,
} from '../rules/schema.js';
import {
    evaluatePrefixRules,
    evaluateNetworkRules,
} from '../rules/evaluator.js';
import { isBannedPrefix, appendAllowPrefixRule } from '../rules/persistence.js';
import { ApprovalStore } from '../rules/approval-store.js';
import { loadRules, type RuleSet } from '../rules/loader.js';

/** Per-evaluation outcome for a single command. */
export type EvaluationRequirement =
    | { type: 'skip'; reason: string; command?: undefined; request?: undefined }
    | {
          type: 'needs-approval';
          reason?: string;
          command?: undefined;
          request: ApprovalRequest;
      }
    | {
          type: 'forbidden';
          reason: string;
          command: readonly string[];
          request?: undefined;
      };

/** A single user-facing approval request. */
export interface ApprovalRequest {
    callId: string;
    command: readonly string[];
    cwd?: string;
    reason: string;
    /** Optional amendment proposal — present if appending an allow rule would
     * resolve the user's intent without a blanket override. */
    proposedAmendment?: ProposedAmendment;
    /** User-selectable decisions. */
    availableDecisions: readonly string[];
}

/** A proposed rule amendment that, if accepted, would allow this command in
 * the future. */
export interface ProposedAmendment {
    rulePrefix: readonly string[];
    filePath: string;
}

/** Engine construction options. */
export interface ExecPolicyManagerOptions {
    /** Directory to scan for `*.rules.json` on {@link loadRules}. */
    configDir?: string;
    /** Default file for new rule amendments. */
    defaultRulesFile?: string;
    /** Seed the engine with rules directly (skips `loadRules`). */
    rules?: readonly PolicyRule[];
}

/** Network request context for {@link ExecPolicyManager.evaluateNetwork}. */
export interface NetworkRequestInfo {
    host: string;
    port: number;
    protocol: 'http' | 'https';
}

/** Context passed to `evaluate` / `evaluateNetwork` / `createHooks`. */
export interface EvaluationContext {
    approvalPolicy: ApprovalPolicy;
    cwd?: string;
    env?: Readonly<Record<string, string>>;
}

/** Network evaluation outcome. */
export type NetworkEvaluation =
    | { type: 'skip'; reason: string }
    | { type: 'needs-approval'; request: ApprovalRequest }
    | { type: 'forbidden'; reason: string; command: readonly string[] };

/**
 * Heuristic guess of which network protocol a request is for, based on port.
 * Mirrors's `inferNetworkProtocol` (line 38792).
 *
 * @public
 */
export function inferNetworkProtocol(port: number): 'http' | 'https' {
    return port === 443 ? 'https' : 'http';
}

/**
 * Top-level policy engine. Reverse-engineered from lines 38516–38794.
 *
 * @public
 */
export class ExecPolicyManager {
    approvalStore = new ApprovalStore();
    configDir: string | undefined;
    defaultRulesFile: string | undefined;
    prefixRules: PolicyRule[] = [];
    networkRules: PolicyRule[] = [];
    ruleSets: RuleSet[] = [];
    callIdCounter = 0;

    constructor(options: ExecPolicyManagerOptions = {}) {
        this.configDir = options.configDir;
        this.defaultRulesFile = options.defaultRulesFile;
        if (options.rules) {
            this.prefixRules = options.rules.filter((r) => r.kind === 'prefix');
            this.networkRules = options.rules.filter((r) => r.kind === 'network');
        }
    }

    /** Read rule files from `configDir` and merge into this engine. */
    async loadRules(): Promise<void> {
        if (!this.configDir) {
            return;
        }
        this.ruleSets = await loadRules(this.configDir);
        const allRules = this.ruleSets.flatMap((s) => s.rules);
        this.prefixRules = allRules.filter((r) => r.kind === 'prefix');
        this.networkRules = allRules.filter((r) => r.kind === 'network');
    }

    /**
     * Evaluate the strongest requirement for a (possibly shell-wrapped)
     * argv. Returns the first `forbidden` if any sub-command is forbidden,
     * otherwise the first `needs-approval`, otherwise `skip`.
     *
     * @public
     */
    evaluate(argv: readonly string[], context: EvaluationContext): EvaluationRequirement {
        const subCommands = parseCommand(argv);
        let worstRequirement: EvaluationRequirement = {
            type: 'skip',
            reason: 'all sub-commands passed',
        };
        for (const subCmd of subCommands) {
            const req = this.evaluateSingle(subCmd, context);
            if (req.type === 'forbidden') {
                return req;
            }
            if (req.type === 'needs-approval' && worstRequirement.type === 'skip') {
                worstRequirement = req;
            }
        }
        return worstRequirement;
    }

    /** Single-command evaluation (no shell-wrapping). @public */
    evaluateSingle(argv: readonly string[], context: EvaluationContext): EvaluationRequirement {
        // Step A: Check session approval store
        if (this.approvalStore.isApprovedForSession(argv)) {
            return { type: 'skip', reason: 'previously approved for session' };
        }
        // Step B: Evaluate prefix rules
        const ruleDecision = evaluatePrefixRules(argv, this.prefixRules);
        if (ruleDecision === 'allow') {
            return { type: 'skip', reason: 'matched allow rule' };
        }
        if (ruleDecision === 'forbidden') {
            return {
                type: 'forbidden',
                reason: 'matched forbidden rule',
                command: argv,
            };
        }
        // Step C: Heuristic classification
        const classification = classifyCommand(argv);
        // Step D: Apply approval mode
        const { approvalPolicy } = context;
        // If a rule explicitly says "prompt"
        if (ruleDecision === 'prompt') {
            if (approvalPolicy === 'never') {
                return {
                    type: 'forbidden',
                    reason: "prompt required by rule, but approval mode is 'never'",
                    command: argv,
                };
            }
            return {
                type: 'needs-approval',
                request: this.buildRequest(argv, context, 'matched prompt rule'),
            };
        }
        // No rule matched — use heuristics + approval mode
        switch (approvalPolicy) {
            case 'never':
                if (classification.safety === 'dangerous') {
                    return {
                        type: 'forbidden',
                        reason: `dangerous command in never-prompt mode: ${classification.reason}`,
                        command: argv,
                    };
                }
                return { type: 'skip', reason: 'never-prompt mode: auto-approved' };
            case 'on-request':
                if (classification.safety === 'dangerous') {
                    return {
                        type: 'forbidden',
                        reason: `dangerous command: ${classification.reason}`,
                        command: argv,
                    };
                }
                return { type: 'skip', reason: 'on-request mode: not flagged' };
            case 'unless-trusted':
                if (classification.safety === 'safe') {
                    return { type: 'skip', reason: 'safe command in unless-trusted mode' };
                }
                if (classification.safety === 'dangerous') {
                    return {
                        type: 'forbidden',
                        reason: `dangerous command: ${classification.reason}`,
                        command: argv,
                    };
                }
                return {
                    type: 'needs-approval',
                    request: this.buildRequest(argv, context, 'unknown command in unless-trusted mode'),
                };
            default:
                return {
                    type: 'forbidden',
                    reason: `unsupported approval policy: ${String(approvalPolicy)}`,
                    command: argv,
                };
        }
    }

    /**
     * Evaluate a single network request against this engine's network rules.
     * @public
     */
    evaluateNetwork(
        host: string,
        port: number,
        protocol: 'http' | 'https',
        context: EvaluationContext,
    ): NetworkEvaluation {
        const requestKey = this.createNetworkRequestKey(host, port, protocol);
        if (this.approvalStore.isApprovedForSession(requestKey)) {
            return { type: 'skip', reason: 'previously approved network request for session' };
        }
        const ruleDecision = evaluateNetworkRules(host, protocol, this.networkRules);
        if (ruleDecision === 'allow') {
            return { type: 'skip', reason: 'matched allow network rule' };
        }
        if (ruleDecision === 'forbidden') {
            return {
                type: 'forbidden',
                reason: 'matched forbidden network rule',
                command: requestKey,
            };
        }
        if (ruleDecision === 'prompt') {
            if (context.approvalPolicy === 'never') {
                return {
                    type: 'forbidden',
                    reason: "network prompt required by rule, but approval mode is 'never'",
                    command: requestKey,
                };
            }
            return {
                type: 'needs-approval',
                request: this.buildRequest(
                    requestKey,
                    context,
                    `network request to ${protocol}://${host}:${port}`,
                ),
            };
        }
        if (context.approvalPolicy === 'unless-trusted') {
            return {
                type: 'needs-approval',
                request: this.buildRequest(
                    requestKey,
                    context,
                    `unknown network request to ${protocol}://${host}:${port}`,
                ),
            };
        }
        return { type: 'skip', reason: 'network request not flagged by policy' };
    }

    /** Build an ApprovalRequest envelope. */
    buildRequest(
        argv: readonly string[],
        context: EvaluationContext,
        reason: string,
    ): ApprovalRequest {
        const callId = String(++this.callIdCounter);
        const amendment = this.deriveAmendment(argv);
        const availableDecisions: string[] = [
            'approved',
            'approved-for-session',
            'denied',
            'abort',
        ];
        if (amendment) {
            availableDecisions.splice(2, 0, 'approved-amendment');
        }
        return {
            callId,
            command: argv,
            cwd: context.cwd,
            reason,
            proposedAmendment: amendment,
            availableDecisions,
        };
    }

    /** Derive a proposed amendment (if any) for the given argv. */
    deriveAmendment(argv: readonly string[]): ProposedAmendment | undefined {
        if (argv.length === 0) {
            return undefined;
        }
        const [firstArg] = argv;
        if (isBannedPrefix(argv as string[])) {
            return undefined;
        }
        if (argv.length > 1 && firstArg !== undefined && isBannedPrefix([firstArg])) {
            return undefined;
        }
        const filePath =
            this.defaultRulesFile ??
            (this.configDir ? `${this.configDir}/default.rules.json` : undefined);
        if (!filePath) {
            return undefined;
        }
        return { rulePrefix: argv, filePath };
    }

    /** Persist a user decision for the given argv. */
    recordDecision(argv: readonly string[], decision: ApprovalDecision): void {
        this.approvalStore.set(argv, decision);
    }

    /** Append a proposed amendment to the file and re-load rules. */
    async appendRule(amendment: ProposedAmendment): Promise<void> {
        await appendAllowPrefixRule(amendment.filePath, [...amendment.rulePrefix]);
        await this.loadRules();
    }

    /** Wire this engine into a sandbox's approval callbacks. */
    createHooks(
        context: EvaluationContext,
        opts: { onApprovalNeeded: (req: ApprovalRequest) => Promise<{ decision: ApprovalDecision }> },
    ): {
        onNetworkRequest: (req: { host: string; port: number; protocol?: 'http' | 'https' }) => Promise<boolean>;
        onExecRequest: (argv: readonly string[]) => Promise<boolean>;
    } {
        return {
            onNetworkRequest: async (req) => {
                const protocol = req.protocol ?? inferNetworkProtocol(req.port);
                const requirement = this.evaluateNetwork(req.host, req.port, protocol, context);
                if (requirement.type === 'skip') {
                    return true;
                }
                if (requirement.type === 'forbidden') {
                    return false;
                }
                const response = await opts.onApprovalNeeded(requirement.request);
                this.recordDecision(
                    this.createNetworkRequestKey(req.host, req.port, protocol),
                    response.decision,
                );
                return (
                    response.decision === 'approved' ||
                    response.decision === 'approved-for-session' ||
                    response.decision === 'approved-amendment'
                );
            },
            onExecRequest: async (argv) => {
                const requirement = this.evaluate(argv, context);
                if (requirement.type === 'skip') {
                    return true;
                }
                if (requirement.type === 'forbidden') {
                    return false;
                }
                const response = await opts.onApprovalNeeded(requirement.request);
                this.recordDecision(argv, response.decision);
                return (
                    response.decision === 'approved' ||
                    response.decision === 'approved-for-session' ||
                    response.decision === 'approved-amendment'
                );
            },
        };
    }

    /** Return all loaded rules. */
    getRules(): readonly PolicyRule[] {
        return [...this.prefixRules, ...this.networkRules];
    }

    /** Build a stable key for a network request. */
    createNetworkRequestKey(host: string, port: number, protocol: 'http' | 'https'): readonly string[] {
        return ['__network__', protocol, host, String(port)];
    }
}
