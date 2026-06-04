/**
 * Prefix / network rule evaluators.
 *
 * Reverse-engineered from
 * inferred from `evaluatePrefixRules` / `evaluateNetworkRules` call sites at
 * 38567 / 38659).
 *
 * Matches a concrete argv against the pattern in a prefix rule. An inner
 * `string[]` pattern element matches if the actual argv token equals any one of
 * the alternates at that position.
 *
 * @public
 */

import type { Decision, NetworkRule, PatternElement, PolicyRule, PrefixRule } from './schema.js';

/** Returned decision of {@link evaluatePrefixRules} / {@link evaluateNetworkRules}. */
export type RuleDecision = Decision | undefined;

/**
 * Match an argv against a single prefix rule's pattern.
 *
 * The pattern is a sequence of `PatternElement`s. Each `PatternElement` is
 * either a single string (literal match) or a `string[]` (any-of match).
 *
 * @public
 */
export function argvMatchesPattern(argv: readonly string[], pattern: readonly PatternElement[]): boolean {
    if (argv.length < pattern.length) {
        return false;
    }
    for (let i = 0; i < pattern.length; i++) {
        const pat = pattern[i];
        const arg = argv[i];
        if (pat === undefined || arg === undefined) {
            return false;
        }
        if (Array.isArray(pat)) {
            if (!pat.includes(arg)) {
                return false;
            }
        } else {
            if (pat !== arg) {
                return false;
            }
        }
    }
    return true;
}

/**
 * Walk a list of prefix rules and return the decision of the first matching
 * rule, or `undefined` if none match.
 *
 * Order matters — 's evaluator stops at the first match, so users should
 * put their deny rules first.
 *
 * @public
 */
export function evaluatePrefixRules(argv: readonly string[], rules: readonly PolicyRule[]): RuleDecision {
    for (const rule of rules) {
        if (rule.kind !== 'prefix') {
            continue;
        }
        const pr: PrefixRule = rule;
        if (argvMatchesPattern(argv, pr.pattern)) {
            return pr.decision;
        }
    }
    return undefined;
}

/**
 * Walk a list of network rules and return the decision of the first matching
 * rule. `host` is matched case-insensitively; `protocol === 'any'` matches
 * either `http` or `https`.
 *
 * @public
 */
export function evaluateNetworkRules(
    host: string,
    protocol: 'http' | 'https',
    rules: readonly PolicyRule[],
): RuleDecision {
    const hostLower = host.toLowerCase();
    for (const rule of rules) {
        if (rule.kind !== 'network') {
            continue;
        }
        const nr: NetworkRule = rule;
        if (nr.host.toLowerCase() !== hostLower) {
            continue;
        }
        if (nr.protocol !== 'any' && nr.protocol !== protocol) {
            continue;
        }
        return nr.decision;
    }
    return undefined;
}
