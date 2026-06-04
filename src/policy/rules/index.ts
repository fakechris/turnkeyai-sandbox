/**
 * Public surface of the rules layer.
 * @public
 */

export {
    isPatternElement,
    isDecision,
    isPrefixRule,
    isNetworkRule,
    isPolicyRule,
    isRuleFile,
    validateRuleFile,
} from './schema.js';
export type {
    Decision,
    PatternElement,
    PrefixRule,
    NetworkRule,
    PolicyRule,
} from './schema.js';

export { BANNED_RULE_PREFIXES, isBannedPrefix, appendAllowPrefixRule } from './persistence.js';

export { ApprovalStore } from './approval-store.js';
export type { ApprovalKey, StoredDecision } from './approval-store.js';

export { argvMatchesPattern, evaluatePrefixRules, evaluateNetworkRules } from './evaluator.js';
export type { RuleDecision } from './evaluator.js';

export { loadRules, loadRuleFile } from './loader.js';
export type { RuleSet } from './loader.js';
