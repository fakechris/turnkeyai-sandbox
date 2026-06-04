import { describe, expect, it } from 'vitest';
import {
    ExecPolicyManager,
    inferNetworkProtocol,
} from '../../../src/policy/engine/exec-policy-manager.js';
import type { ApprovalRequest } from '../../../src/policy/engine/exec-policy-manager.js';
import type { EvaluationContext } from '../../../src/policy/engine/exec-policy-manager.js';
import type { PolicyRule } from '../../../src/policy/rules/schema.js';

const defaultCtx: EvaluationContext = { approvalPolicy: 'unless-trusted' };
const onRequestCtx: EvaluationContext = { approvalPolicy: 'on-request' };
const neverCtx: EvaluationContext = { approvalPolicy: 'never' };

describe('ExecPolicyManager basic', () => {
    it('starts with no rules', () => {
        const m = new ExecPolicyManager();
        expect(m.getRules()).toEqual([]);
    });

    it('constructor accepts inline rules', () => {
        const rules: PolicyRule[] = [
            { kind: 'prefix', pattern: ['ls'], decision: 'allow' },
            { kind: 'network', host: 'x.com', protocol: 'any', decision: 'forbidden' },
        ];
        const m = new ExecPolicyManager({ rules });
        expect(m.getRules()).toEqual(rules);
    });
});

describe('ExecPolicyManager.evaluate — never mode', () => {
    it('forbids a dangerous command', () => {
        const m = new ExecPolicyManager();
        const r = m.evaluate(['rm', '-rf', '/tmp'], neverCtx);
        expect(r.type).toBe('forbidden');
        expect(r.type === 'forbidden' && r.reason).toMatch(/dangerous/);
    });

    it('skips a safe command', () => {
        const m = new ExecPolicyManager();
        const r = m.evaluate(['ls', '-la'], neverCtx);
        expect(r.type).toBe('skip');
    });

    it('skips an unknown command in never mode (auto-approved, no prompt)', () => {
        const m = new ExecPolicyManager();
        const r = m.evaluate(['curl', 'https://example.com'], neverCtx);
        expect(r.type).toBe('skip');
    });
});

describe('ExecPolicyManager.evaluate — on-request mode', () => {
    it('forbids dangerous', () => {
        const m = new ExecPolicyManager();
        expect(m.evaluate(['rm', '-rf', '/'], onRequestCtx).type).toBe('forbidden');
    });

    it('skips safe', () => {
        const m = new ExecPolicyManager();
        expect(m.evaluate(['ls'], onRequestCtx).type).toBe('skip');
    });

    it('skips unknown (not flagged)', () => {
        const m = new ExecPolicyManager();
        expect(m.evaluate(['curl', 'https://x.com'], onRequestCtx).type).toBe('skip');
    });
});

describe('ExecPolicyManager.evaluate — unless-trusted mode', () => {
    it('skips safe', () => {
        const m = new ExecPolicyManager();
        expect(m.evaluate(['ls'], defaultCtx).type).toBe('skip');
    });

    it('forbids dangerous', () => {
        const m = new ExecPolicyManager();
        expect(m.evaluate(['rm', '-rf', '/'], defaultCtx).type).toBe('forbidden');
    });

    it('needs-approval for unknown', () => {
        const m = new ExecPolicyManager();
        const r = m.evaluate(['curl', 'https://x.com'], defaultCtx);
        expect(r.type).toBe('needs-approval');
    });
});

describe('ExecPolicyManager.evaluate — prefix rules take precedence', () => {
    it('allow rule skips safe classification', () => {
        const m = new ExecPolicyManager({
            rules: [{ kind: 'prefix', pattern: ['custom-cmd'], decision: 'allow' }],
        });
        // custom-cmd would normally be unknown; allow rule skips it
        expect(m.evaluate(['custom-cmd', 'arg'], defaultCtx).type).toBe('skip');
    });

    it('forbidden rule wins over safe classification', () => {
        const m = new ExecPolicyManager({
            rules: [{ kind: 'prefix', pattern: ['ls'], decision: 'forbidden' }],
        });
        expect(m.evaluate(['ls'], defaultCtx).type).toBe('forbidden');
    });

    it('prompt rule triggers approval even in safe classification', () => {
        const m = new ExecPolicyManager({
            rules: [{ kind: 'prefix', pattern: ['ls'], decision: 'prompt' }],
        });
        const r = m.evaluate(['ls'], defaultCtx);
        expect(r.type).toBe('needs-approval');
    });

    it('prompt rule becomes forbidden in never mode', () => {
        const m = new ExecPolicyManager({
            rules: [{ kind: 'prefix', pattern: ['ls'], decision: 'prompt' }],
        });
        const r = m.evaluate(['ls'], neverCtx);
        expect(r.type).toBe('forbidden');
    });
});

describe('ExecPolicyManager.evaluate — shell-wrapped commands', () => {
    it('forbids dangerous sub-command in shell wrapper', () => {
        const m = new ExecPolicyManager();
        // bash -c 'rm -rf /' should be forbidden because rm -rf is forbidden.
        const r = m.evaluate(['bash', '-c', 'rm -rf /'], defaultCtx);
        expect(r.type).toBe('forbidden');
    });

    it('skips when all sub-commands pass', () => {
        const m = new ExecPolicyManager();
        const r = m.evaluate(['bash', '-c', 'ls && cat foo'], defaultCtx);
        expect(r.type).toBe('skip');
    });

    it('returns needs-approval if any sub-command needs it', () => {
        const m = new ExecPolicyManager();
        const r = m.evaluate(['bash', '-c', 'ls && curl https://x.com'], defaultCtx);
        expect(r.type).toBe('needs-approval');
    });
});

describe('ExecPolicyManager.evaluate — session approval store', () => {
    it('skips a previously approved command', () => {
        const m = new ExecPolicyManager();
        m.approvalStore.set(['curl', 'https://x.com'], 'approved');
        const r = m.evaluate(['curl', 'https://x.com'], defaultCtx);
        expect(r.type).toBe('skip');
    });

    it('denied does not persist; next call re-prompts', () => {
        const m = new ExecPolicyManager();
        m.approvalStore.set(['curl', 'https://x.com'], 'denied');
        const r = m.evaluate(['curl', 'https://x.com'], defaultCtx);
        expect(r.type).toBe('needs-approval');
    });
});

describe('ExecPolicyManager.evaluateNetwork', () => {
    it('skips on allow', () => {
        const m = new ExecPolicyManager({
            rules: [{ kind: 'network', host: 'api.x.com', protocol: 'any', decision: 'allow' }],
        });
        const r = m.evaluateNetwork('api.x.com', 443, 'https', onRequestCtx);
        expect(r.type).toBe('skip');
    });

    it('forbids on forbidden', () => {
        const m = new ExecPolicyManager({
            rules: [{ kind: 'network', host: 'evil.com', protocol: 'any', decision: 'forbidden' }],
        });
        const r = m.evaluateNetwork('evil.com', 443, 'https', onRequestCtx);
        expect(r.type).toBe('forbidden');
    });

    it('needs-approval for unknown host in unless-trusted', () => {
        const m = new ExecPolicyManager();
        const r = m.evaluateNetwork('unknown.com', 443, 'https', defaultCtx);
        expect(r.type).toBe('needs-approval');
    });

    it('skips unknown host in on-request mode (no policy at all)', () => {
        const m = new ExecPolicyManager();
        const r = m.evaluateNetwork('unknown.com', 443, 'https', onRequestCtx);
        expect(r.type).toBe('skip');
    });

    it('skips network previously approved for session', () => {
        const m = new ExecPolicyManager();
        const key = m.createNetworkRequestKey('unknown.com', 443, 'https');
        m.approvalStore.set(key, 'approved');
        const r = m.evaluateNetwork('unknown.com', 443, 'https', defaultCtx);
        expect(r.type).toBe('skip');
    });
});

describe('ExecPolicyManager.createHooks', () => {
    it('returns onNetworkRequest and onExecRequest hooks', () => {
        const m = new ExecPolicyManager();
        const hooks = m.createHooks(defaultCtx, {
            onApprovalNeeded: async () => ({ decision: 'denied' as const }),
        });
        expect(typeof hooks.onNetworkRequest).toBe('function');
        expect(typeof hooks.onExecRequest).toBe('function');
    });

    it('onExecRequest returns true when policy skips', async () => {
        const m = new ExecPolicyManager();
        const hooks = m.createHooks(defaultCtx, {
            onApprovalNeeded: async () => ({ decision: 'denied' as const }),
        });
        expect(await hooks.onExecRequest(['ls'])).toBe(true);
    });

    it('onExecRequest returns false when policy forbids', async () => {
        const m = new ExecPolicyManager();
        const hooks = m.createHooks(defaultCtx, {
            onApprovalNeeded: async () => ({ decision: 'denied' as const }),
        });
        expect(await hooks.onExecRequest(['rm', '-rf', '/'])).toBe(false);
    });

    it('onExecRequest calls onApprovalNeeded and respects user decision', async () => {
        const m = new ExecPolicyManager();
        let captured: ApprovalRequest | undefined;
        const hooks = m.createHooks(defaultCtx, {
            onApprovalNeeded: async (req) => {
                captured = req;
                return { decision: 'approved' };
            },
        });
        const result = await hooks.onExecRequest(['curl', 'https://x.com']);
        expect(result).toBe(true);
        expect(captured).toBeDefined();
        expect(captured?.command).toEqual(['curl', 'https://x.com']);
    });

    it('onNetworkRequest works for unknown host in unless-trusted mode', async () => {
        const m = new ExecPolicyManager();
        const hooks = m.createHooks(defaultCtx, {
            onApprovalNeeded: async () => ({ decision: 'approved' as const }),
        });
        const result = await hooks.onNetworkRequest({ host: 'unknown.com', port: 443 });
        expect(result).toBe(true);
    });

    it('onNetworkRequest defaults protocol by port', async () => {
        const m = new ExecPolicyManager();
        const calls: Array<{ host: string; port: number; protocol?: 'http' | 'https' }> = [];
        const hooks = m.createHooks(defaultCtx, {
            onApprovalNeeded: async (req) => {
                calls.push({
                    host: (req.command[2] ?? ''),
                    port: Number(req.command[3] ?? 0),
                    protocol: undefined,
                });
                return { decision: 'approved' as const };
            },
        });
        await hooks.onNetworkRequest({ host: 'x.com', port: 443 });
        // The request stores the argv form: [__, protocol, host, port]
        // Since inferNetworkProtocol(443) === 'https', the call's recorded command has 'https'
        expect(calls[0]?.port).toBe(443);
    });
});

describe('ExecPolicyManager.deriveAmendment', () => {
    it('returns undefined for banned prefix', () => {
        const m = new ExecPolicyManager({ configDir: '/tmp/x' });
        expect(m.deriveAmendment(['bash', '-c'])).toBeUndefined();
    });

    it('returns undefined for first-arg that is a banned prefix', () => {
        const m = new ExecPolicyManager({ configDir: '/tmp/x' });
        expect(m.deriveAmendment(['sudo', 'ls'])).toBeUndefined();
    });

    it('returns an amendment when no config dir set', () => {
        const m = new ExecPolicyManager({ defaultRulesFile: '/tmp/default.rules.json' });
        const a = m.deriveAmendment(['ls', '-la']);
        expect(a).toEqual({ rulePrefix: ['ls', '-la'], filePath: '/tmp/default.rules.json' });
    });

    it('uses configDir + default.rules.json when no defaultRulesFile set', () => {
        const m = new ExecPolicyManager({ configDir: '/etc/foo' });
        const a = m.deriveAmendment(['ls']);
        expect(a).toEqual({ rulePrefix: ['ls'], filePath: '/etc/foo/default.rules.json' });
    });
});

describe('inferNetworkProtocol', () => {
    it('returns https for port 443', () => {
        expect(inferNetworkProtocol(443)).toBe('https');
    });

    it('returns http for any other port', () => {
        expect(inferNetworkProtocol(80)).toBe('http');
        expect(inferNetworkProtocol(8080)).toBe('http');
        expect(inferNetworkProtocol(0)).toBe('http');
    });
});
