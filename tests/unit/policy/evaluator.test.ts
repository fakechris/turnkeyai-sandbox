import { describe, expect, it } from 'vitest';
import {
    argvMatchesPattern,
    evaluateNetworkRules,
    evaluatePrefixRules,
} from '../../../src/policy/rules/evaluator.js';
import type { PolicyRule } from '../../../src/policy/rules/schema.js';

describe('argvMatchesPattern', () => {
    it('matches a literal-string pattern', () => {
        expect(argvMatchesPattern(['npm', 'test'], ['npm', 'test'])).toBe(true);
    });

    it('rejects mismatched literal strings', () => {
        expect(argvMatchesPattern(['npm', 'test'], ['npm', 'run'])).toBe(false);
    });

    it('rejects when argv is shorter than pattern', () => {
        expect(argvMatchesPattern(['npm'], ['npm', 'test'])).toBe(false);
    });

    it('allows argv to be longer than pattern (prefix match)', () => {
        expect(argvMatchesPattern(['npm', 'test', '--watch'], ['npm', 'test'])).toBe(true);
    });

    it('matches when inner array element matches any', () => {
        expect(argvMatchesPattern(['git', 'status'], [['git', 'gh'], 'status'])).toBe(true);
        expect(argvMatchesPattern(['gh', 'status'], [['git', 'gh'], 'status'])).toBe(true);
        expect(argvMatchesPattern(['hg', 'status'], [['git', 'gh'], 'status'])).toBe(false);
    });
});

describe('evaluatePrefixRules', () => {
    const rules: PolicyRule[] = [
        { kind: 'prefix', pattern: ['npm', 'test'], decision: 'allow' },
        { kind: 'prefix', pattern: ['cargo', 'test'], decision: 'prompt' },
        { kind: 'prefix', pattern: ['dangerous-cmd'], decision: 'forbidden' },
    ];

    it('returns the first matching decision', () => {
        expect(evaluatePrefixRules(['npm', 'test'], rules)).toBe('allow');
        expect(evaluatePrefixRules(['cargo', 'test', '--release'], rules)).toBe('prompt');
        expect(evaluatePrefixRules(['dangerous-cmd', 'arg'], rules)).toBe('forbidden');
    });

    it('returns undefined when no rule matches', () => {
        expect(evaluatePrefixRules(['ls', '-la'], rules)).toBeUndefined();
    });

    it('skips network rules', () => {
        const mixed: PolicyRule[] = [
            { kind: 'network', host: 'x.com', protocol: 'any', decision: 'forbidden' },
            { kind: 'prefix', pattern: ['ls'], decision: 'allow' },
        ];
        expect(evaluatePrefixRules(['ls'], mixed)).toBe('allow');
    });
});

describe('evaluateNetworkRules', () => {
    const rules: PolicyRule[] = [
        { kind: 'network', host: 'example.com', protocol: 'any', decision: 'allow' },
        { kind: 'network', host: 'evil.com', protocol: 'https', decision: 'forbidden' },
        { kind: 'network', host: 'mixed.com', protocol: 'http', decision: 'prompt' },
    ];

    it('matches host case-insensitively', () => {
        expect(evaluateNetworkRules('EXAMPLE.com', 'https', rules)).toBe('allow');
    });

    it('matches when protocol is "any"', () => {
        expect(evaluateNetworkRules('example.com', 'http', rules)).toBe('allow');
        expect(evaluateNetworkRules('example.com', 'https', rules)).toBe('allow');
    });

    it('respects the protocol field', () => {
        // mixed.com is only "prompt" for http, not for https
        expect(evaluateNetworkRules('mixed.com', 'http', rules)).toBe('prompt');
        expect(evaluateNetworkRules('mixed.com', 'https', rules)).toBeUndefined();
    });

    it('returns forbidden on protocol match', () => {
        expect(evaluateNetworkRules('evil.com', 'https', rules)).toBe('forbidden');
    });

    it('returns undefined when host does not match', () => {
        expect(evaluateNetworkRules('other.com', 'https', rules)).toBeUndefined();
    });

    it('skips prefix rules', () => {
        const mixed: PolicyRule[] = [
            { kind: 'prefix', pattern: ['ls'], decision: 'forbidden' },
            { kind: 'network', host: 'example.com', protocol: 'any', decision: 'allow' },
        ];
        expect(evaluateNetworkRules('example.com', 'https', mixed)).toBe('allow');
    });
});
