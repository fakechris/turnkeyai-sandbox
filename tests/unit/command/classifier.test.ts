import { describe, expect, it } from 'vitest';
import {
    classifyCommand,
    isDangerousCommand,
    isSafeCommand,
} from '../../../src/policy/command/classifier.js';

describe('classifyCommand', () => {
    it('returns unknown for empty argv', () => {
        expect(classifyCommand([])).toMatchObject({ safety: 'unknown' });
    });

    it('classifies all unconditional-safe commands as safe', () => {
        for (const cmd of [
            'cat',
            'cd',
            'cut',
            'echo',
            'expr',
            'false',
            'grep',
            'head',
            'id',
            'ls',
            'nl',
            'paste',
            'pwd',
            'rev',
            'seq',
            'stat',
            'tail',
            'tr',
            'true',
            'uname',
            'uniq',
            'wc',
            'which',
            'whoami',
        ]) {
            expect(classifyCommand([cmd, 'foo'])).toMatchObject({ safety: 'safe' });
        }
    });

    it('classifies ls -la /tmp as safe', () => {
        expect(classifyCommand(['ls', '-la', '/tmp'])).toMatchObject({ safety: 'safe' });
    });

    it('classifies git status as safe', () => {
        expect(classifyCommand(['git', 'status'])).toMatchObject({ safety: 'safe' });
    });

    it('classifies git config as unknown', () => {
        expect(classifyCommand(['git', 'config', '--global', 'foo'])).toMatchObject({
            safety: 'unknown',
        });
    });

    it('classifies git log -p as safe (p is allowed for log)', () => {
        expect(classifyCommand(['git', 'log', '-p'])).toMatchObject({ safety: 'safe' });
    });

    it('classifies git push as unknown', () => {
        expect(classifyCommand(['git', 'push'])).toMatchObject({ safety: 'unknown' });
    });

    it('classifies find with -exec as unknown', () => {
        expect(classifyCommand(['find', '/tmp', '-exec', 'rm', '{}', ';'])).toMatchObject({
            safety: 'unknown',
        });
    });

    it('classifies plain find as safe', () => {
        expect(classifyCommand(['find', '/tmp', '-name', '*.log'])).toMatchObject({
            safety: 'safe',
        });
    });

    it('classifies rg with --pre as unknown', () => {
        expect(classifyCommand(['rg', '--pre', 'cat', 'foo', 'bar'])).toMatchObject({
            safety: 'unknown',
        });
    });

    it('classifies plain rg as safe', () => {
        expect(classifyCommand(['rg', 'pattern', 'file.txt'])).toMatchObject({ safety: 'safe' });
    });

    it('classifies base64 -o as unknown (writes file)', () => {
        expect(classifyCommand(['base64', '-o', 'out.txt', 'in.txt'])).toMatchObject({
            safety: 'unknown',
        });
    });

    it('classifies plain base64 as safe', () => {
        expect(classifyCommand(['base64', 'in.txt'])).toMatchObject({ safety: 'safe' });
    });

    it('classifies sed -n 5p as safe (exactly 2 args after sed)', () => {
        // requires exactly 2 args after sed (sed, -n, <pattern>).
        // The file argument would put it in the 3-arg branch (unknown).
        expect(classifyCommand(['sed', '-n', '5p'])).toMatchObject({ safety: 'safe' });
        expect(classifyCommand(['sed', '-n', '3,10p'])).toMatchObject({ safety: 'safe' });
    });

    it('classifies sed with a filename as unknown (extra arg)', () => {
        expect(classifyCommand(['sed', '-n', '5p', 'file.txt'])).toMatchObject({
            safety: 'unknown',
        });
    });

    it('classifies sed -i as unknown', () => {
        expect(classifyCommand(['sed', '-i', 's/foo/bar/', 'file.txt'])).toMatchObject({
            safety: 'unknown',
        });
    });

    it('classifies rm -rf as dangerous', () => {
        expect(classifyCommand(['rm', '-rf', '/tmp/foo'])).toMatchObject({ safety: 'dangerous' });
    });

    it('classifies rm -fr as dangerous', () => {
        expect(classifyCommand(['rm', '-fr', '/tmp/foo'])).toMatchObject({ safety: 'dangerous' });
    });

    it('classifies rm -rfi as dangerous (combined short flag contains f)', () => {
        expect(classifyCommand(['rm', '-rfi'])).toMatchObject({ safety: 'dangerous' });
    });

    it('classifies rm --force as dangerous', () => {
        expect(classifyCommand(['rm', '--force', 'foo'])).toMatchObject({ safety: 'dangerous' });
    });

    it('classifies rm with no force flag as unknown', () => {
        expect(classifyCommand(['rm', 'foo'])).toMatchObject({ safety: 'unknown' });
    });

    it('classifies sudo rm -rf as dangerous (preserves inner danger)', () => {
        expect(classifyCommand(['sudo', 'rm', '-rf', '/'])).toMatchObject({
            safety: 'dangerous',
        });
    });

    it('classifies sudo ls as unknown (privilege escalation)', () => {
        expect(classifyCommand(['sudo', 'ls'])).toMatchObject({ safety: 'unknown' });
    });

    it('classifies unknown command as unknown', () => {
        expect(classifyCommand(['curl', 'https://example.com'])).toMatchObject({
            safety: 'unknown',
        });
    });

    it('strips .exe extension before classifying', () => {
        expect(classifyCommand(['git.exe', 'status'])).toMatchObject({ safety: 'safe' });
    });
});

describe('isSafeCommand / isDangerousCommand', () => {
    it('isSafeCommand is true only for safe', () => {
        expect(isSafeCommand(['ls', '-la'])).toBe(true);
        expect(isSafeCommand(['rm', '-rf', '/'])).toBe(false);
        expect(isSafeCommand(['curl', 'https://example.com'])).toBe(false);
    });

    it('isDangerousCommand is true only for dangerous', () => {
        expect(isDangerousCommand(['rm', '-rf', '/'])).toBe(true);
        expect(isDangerousCommand(['ls'])).toBe(false);
        expect(isDangerousCommand(['curl', 'https://example.com'])).toBe(false);
    });
});
