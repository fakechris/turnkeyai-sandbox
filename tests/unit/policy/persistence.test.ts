import { describe, expect, it } from 'vitest';
import {
    BANNED_RULE_PREFIXES,
    isBannedPrefix,
    appendAllowPrefixRule,
} from '../../../src/policy/rules/persistence.js';
import { mkdtemp, rm, writeFile, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

describe('BANNED_RULE_PREFIXES', () => {
    it('contains 40 entries (verbatim from)', () => {
        expect(BANNED_RULE_PREFIXES.length).toBe(40);
    });

    it('includes all the major interpreter wrappers', () => {
        const bannedStrings = BANNED_RULE_PREFIXES.map((b) => b.join(' '));
        expect(bannedStrings).toContain('bash');
        expect(bannedStrings).toContain('bash -c');
        expect(bannedStrings).toContain('bash -lc');
        expect(bannedStrings).toContain('sh');
        expect(bannedStrings).toContain('zsh');
        expect(bannedStrings).toContain('node -e');
        expect(bannedStrings).toContain('python3 -c');
        expect(bannedStrings).toContain('sudo');
        expect(bannedStrings).toContain('osascript');
        expect(bannedStrings).toContain('pwsh -Command');
    });

    it('is frozen', () => {
        // Object.freeze in non-strict mode silently fails; in strict mode
        // it throws TypeError. We test the structural property instead.
        expect(Object.isFrozen(BANNED_RULE_PREFIXES)).toBe(true);
        // Each inner array is also frozen.
        for (const prefix of BANNED_RULE_PREFIXES) {
            expect(Object.isFrozen(prefix)).toBe(true);
        }
    });
});

describe('isBannedPrefix', () => {
    it('matches an exact entry', () => {
        expect(isBannedPrefix(['bash'])).toBe(true);
        expect(isBannedPrefix(['bash', '-c'])).toBe(true);
        expect(isBannedPrefix(['sudo'])).toBe(true);
    });

    it('does not match partial prefixes', () => {
        // bash is banned but "bashscript" is not in the table
        expect(isBannedPrefix(['bashscript'])).toBe(false);
    });

    it('does not match longer args that happen to start with a banned argv', () => {
        // ['bash', '-c', 'ls'] is a 3-element prefix; not in the table
        expect(isBannedPrefix(['bash', '-c', 'ls'])).toBe(false);
    });

    it('does not match shorter prefixes', () => {
        // ['bash'] is in the table; ['bas'] is not
        expect(isBannedPrefix(['bas'])).toBe(false);
    });
});

describe('appendAllowPrefixRule', () => {
    it('writes a new rule file when none exists', async () => {
        const dir = await mkdtemp(join(tmpdir(), 'rule-test-'));
        try {
            const filePath = join(dir, 'test.rules.json');
            await appendAllowPrefixRule(filePath, ['npm', 'test']);
            const content = await readFile(filePath, 'utf-8');
            const parsed = JSON.parse(content);
            expect(parsed).toEqual([
                { kind: 'prefix', pattern: ['npm', 'test'], decision: 'allow' },
            ]);
        } finally {
            await rm(dir, { recursive: true, force: true });
        }
    });

    it('appends to an existing rule file', async () => {
        const dir = await mkdtemp(join(tmpdir(), 'rule-test-'));
        try {
            const filePath = join(dir, 'test.rules.json');
            await writeFile(
                filePath,
                JSON.stringify([{ kind: 'prefix', pattern: ['cargo'], decision: 'allow' }]),
                'utf-8',
            );
            await appendAllowPrefixRule(filePath, ['npm', 'test']);
            const parsed = JSON.parse(await readFile(filePath, 'utf-8'));
            expect(parsed).toEqual([
                { kind: 'prefix', pattern: ['cargo'], decision: 'allow' },
                { kind: 'prefix', pattern: ['npm', 'test'], decision: 'allow' },
            ]);
        } finally {
            await rm(dir, { recursive: true, force: true });
        }
    });

    it('dedups identical rules', async () => {
        const dir = await mkdtemp(join(tmpdir(), 'rule-test-'));
        try {
            const filePath = join(dir, 'test.rules.json');
            await appendAllowPrefixRule(filePath, ['npm', 'test']);
            await appendAllowPrefixRule(filePath, ['npm', 'test']);
            const parsed = JSON.parse(await readFile(filePath, 'utf-8'));
            expect(parsed).toHaveLength(1);
        } finally {
            await rm(dir, { recursive: true, force: true });
        }
    });

    it('refuses to add a banned prefix', async () => {
        const dir = await mkdtemp(join(tmpdir(), 'rule-test-'));
        try {
            const filePath = join(dir, 'test.rules.json');
            await expect(appendAllowPrefixRule(filePath, ['bash', '-c'])).rejects.toThrow(
                /banned/,
            );
        } finally {
            await rm(dir, { recursive: true, force: true });
        }
    });

    it('writes atomically (no .tmp leftovers)', async () => {
        const dir = await mkdtemp(join(tmpdir(), 'rule-test-'));
        try {
            const filePath = join(dir, 'test.rules.json');
            await appendAllowPrefixRule(filePath, ['npm', 'test']);
            const { readdirSync } = await import('node:fs');
            const entries = readdirSync(dir);
            const tmpLeftovers = entries.filter((e) => e.includes('.tmp.'));
            expect(tmpLeftovers).toEqual([]);
        } finally {
            await rm(dir, { recursive: true, force: true });
        }
    });
});
