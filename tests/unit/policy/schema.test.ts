import { describe, expect, it } from 'vitest';
import {
    isDecision,
    isNetworkRule,
    isPatternElement,
    isPolicyRule,
    isPrefixRule,
    isRuleFile,
    validateRuleFile,
} from '../../../src/policy/rules/schema.js';

describe('isPatternElement', () => {
    it('accepts a single string', () => {
        expect(isPatternElement('foo')).toBe(true);
    });

    it('accepts a non-empty string array', () => {
        expect(isPatternElement(['a', 'b'])).toBe(true);
    });

    it('rejects empty arrays', () => {
        expect(isPatternElement([])).toBe(false);
    });

    it('rejects non-string arrays', () => {
        expect(isPatternElement([1, 2])).toBe(false);
    });

    it('rejects other types', () => {
        expect(isPatternElement(42)).toBe(false);
        expect(isPatternElement(null)).toBe(false);
        expect(isPatternElement({})).toBe(false);
    });
});

describe('isDecision', () => {
    it('accepts the three values', () => {
        expect(isDecision('allow')).toBe(true);
        expect(isDecision('prompt')).toBe(true);
        expect(isDecision('forbidden')).toBe(true);
    });

    it('rejects other strings', () => {
        expect(isDecision('deny')).toBe(false);
        expect(isDecision('ALLOW')).toBe(false);
    });
});

describe('isPrefixRule', () => {
    it('accepts a minimal prefix rule', () => {
        expect(
            isPrefixRule({ kind: 'prefix', pattern: ['ls'], decision: 'allow' }),
        ).toBe(true);
    });

    it('accepts a rule with array-element alternation', () => {
        expect(
            isPrefixRule({
                kind: 'prefix',
                pattern: [['git', 'gh'], 'status'],
                decision: 'prompt',
            }),
        ).toBe(true);
    });

    it('rejects unknown kind', () => {
        expect(
            isPrefixRule({ kind: 'unknown', pattern: ['x'], decision: 'allow' }),
        ).toBe(false);
    });

    it('rejects empty pattern', () => {
        expect(
            isPrefixRule({ kind: 'prefix', pattern: [], decision: 'allow' }),
        ).toBe(false);
    });
});

describe('isNetworkRule', () => {
    it('accepts a minimal network rule', () => {
        expect(
            isNetworkRule({ kind: 'network', host: 'example.com', protocol: 'https', decision: 'allow' }),
        ).toBe(true);
    });

    it('accepts the any protocol', () => {
        expect(
            isNetworkRule({ kind: 'network', host: 'x', protocol: 'any', decision: 'forbidden' }),
        ).toBe(true);
    });

    it('rejects empty host', () => {
        expect(
            isNetworkRule({ kind: 'network', host: '', protocol: 'any', decision: 'forbidden' }),
        ).toBe(false);
    });
});

describe('isPolicyRule / isRuleFile / validateRuleFile', () => {
    it('isPolicyRule accepts both rule kinds', () => {
        expect(
            isPolicyRule({ kind: 'prefix', pattern: ['ls'], decision: 'allow' }),
        ).toBe(true);
        expect(
            isPolicyRule({ kind: 'network', host: 'x', protocol: 'any', decision: 'allow' }),
        ).toBe(true);
    });

    it('isRuleFile accepts an array of valid rules', () => {
        const file = [
            { kind: 'prefix', pattern: ['ls'], decision: 'allow' as const },
            { kind: 'network', host: 'x.com', protocol: 'any' as const, decision: 'forbidden' as const },
        ];
        expect(isRuleFile(file)).toBe(true);
        expect(validateRuleFile(file)).toEqual(file);
    });

    it('validateRuleFile throws on invalid input', () => {
        expect(() => validateRuleFile([{ kind: 'oops' }])).toThrow();
        expect(() => validateRuleFile({})).toThrow();
        expect(() => validateRuleFile('not an array')).toThrow();
    });
});
