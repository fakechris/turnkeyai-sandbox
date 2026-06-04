/**
 * Policy rule schema and type guards.
 *
 * Reverse-engineered from
 * `packages/sandbox-policy/src/rules/schema.ts` .
 * We use hand-rolled type guards rather than zod to keep the runtime surface
 * minimal and trivially debuggable.
 *
 * @public
 */

/** Decision a prefix/network rule can take. */
export type Decision = 'allow' | 'prompt' | 'forbidden';

/** A single element in a prefix rule's pattern. */
export type PatternElement = string | string[];

/** A single arg prefix that should be matched. */
export type PrefixRule = {
    kind: 'prefix';
    /** Sequence of argv tokens to match. An inner `string[]` element
     *  means "match any one of these at this position". */
    pattern: PatternElement[];
    decision: Decision;
};

/** A single host / network rule. */
export type NetworkRule = {
    kind: 'network';
    host: string;
    protocol: 'http' | 'https' | 'any';
    decision: Decision;
};

/** Discriminated union of every rule kind we support. */
export type PolicyRule = PrefixRule | NetworkRule;

/** Type-guard helpers (replacing zod in 's bundle). */

export function isPatternElement(v: unknown): v is PatternElement {
    if (typeof v === 'string') {
        return true;
    }
    if (Array.isArray(v) && v.length > 0 && v.every((x) => typeof x === 'string')) {
        return true;
    }
    return false;
}

export function isDecision(v: unknown): v is Decision {
    return v === 'allow' || v === 'prompt' || v === 'forbidden';
}

export function isPrefixRule(v: unknown): v is PrefixRule {
    if (typeof v !== 'object' || v === null) {
        return false;
    }
    const r = v as Record<string, unknown>;
    return (
        r.kind === 'prefix' &&
        Array.isArray(r.pattern) &&
        r.pattern.length > 0 &&
        (r.pattern as unknown[]).every(isPatternElement) &&
        isDecision(r.decision)
    );
}

export function isNetworkRule(v: unknown): v is NetworkRule {
    if (typeof v !== 'object' || v === null) {
        return false;
    }
    const r = v as Record<string, unknown>;
    return (
        r.kind === 'network' &&
        typeof r.host === 'string' &&
        r.host.length > 0 &&
        (r.protocol === 'http' || r.protocol === 'https' || r.protocol === 'any') &&
        isDecision(r.decision)
    );
}

export function isPolicyRule(v: unknown): v is PolicyRule {
    return isPrefixRule(v) || isNetworkRule(v);
}

export function isRuleFile(v: unknown): v is PolicyRule[] {
    return Array.isArray(v) && v.every(isPolicyRule);
}

/** Throws on the first invalid rule. Useful for parse error UX. */
export function validateRuleFile(v: unknown): PolicyRule[] {
    if (!isRuleFile(v)) {
        throw new TypeError('Rule file is not a PolicyRule[]: ' + JSON.stringify(v).slice(0, 200));
    }
    return v;
}
