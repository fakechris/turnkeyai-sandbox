import { describe, expect, it } from 'vitest';
import {
    getShellWrapInfo,
    isShellWrapped,
    parseCommand,
    tokenizeShellString,
    tokenizePowerShellString,
    tokenizeCmdString,
} from '../../../src/policy/command/parser.js';

describe('getShellWrapInfo', () => {
    it('returns undefined for short argvs', () => {
        expect(getShellWrapInfo(['ls'])).toBeUndefined();
        expect(getShellWrapInfo(['bash'])).toBeUndefined();
    });

    it('detects bash -c', () => {
        expect(getShellWrapInfo(['bash', '-c', 'ls -la'])).toEqual({
            dialect: 'posix',
            commandIndex: 2,
        });
    });

    it('detects bash -lc', () => {
        expect(getShellWrapInfo(['bash', '-lc', 'ls -la'])).toEqual({
            dialect: 'posix',
            commandIndex: 2,
        });
    });

    it('detects sh and zsh', () => {
        expect(getShellWrapInfo(['sh', '-c', 'ls'])).toBeDefined();
        expect(getShellWrapInfo(['zsh', '-lc', 'ls'])).toBeDefined();
        expect(getShellWrapInfo(['/bin/bash', '-c', 'ls'])).toBeDefined();
    });

    it('returns undefined for bash without -c', () => {
        expect(getShellWrapInfo(['bash', '/path/to/script'])).toBeUndefined();
    });

    it('detects powershell -Command', () => {
        expect(getShellWrapInfo(['powershell', '-Command', 'Get-Process'])).toEqual({
            dialect: 'powershell',
            commandIndex: 2,
        });
    });

    it('detects powershell -NoProfile -Command', () => {
        expect(getShellWrapInfo(['pwsh', '-NoProfile', '-Command', 'Get-Process'])).toEqual({
            dialect: 'powershell',
            commandIndex: 3,
        });
    });

    it('detects powershell -EncodedCommand', () => {
        const encoded = Buffer.from('echo hi', 'utf16le').toString('base64');
        expect(getShellWrapInfo(['pwsh', '-EncodedCommand', encoded])).toEqual({
            dialect: 'powershell',
            commandIndex: 2,
            encoded: true,
        });
    });

    it('detects cmd /c', () => {
        expect(getShellWrapInfo(['cmd', '/c', 'dir'])).toEqual({
            dialect: 'cmd',
            commandIndex: 2,
        });
    });
});

describe('isShellWrapped', () => {
    it('is true iff getShellWrapInfo returns non-undefined', () => {
        expect(isShellWrapped(['ls', '-la'])).toBe(false);
        expect(isShellWrapped(['bash', '-c', 'ls'])).toBe(true);
    });
});

describe('tokenizeShellString', () => {
    it('splits on &&', () => {
        expect(tokenizeShellString('ls && cat foo')).toEqual([
            ['ls'],
            ['cat', 'foo'],
        ]);
    });

    it('splits on ||', () => {
        expect(tokenizeShellString('ls || echo failed')).toEqual([
            ['ls'],
            ['echo', 'failed'],
        ]);
    });

    it('splits on ;', () => {
        expect(tokenizeShellString('a; b; c')).toEqual([['a'], ['b'], ['c']]);
    });

    it('splits on |', () => {
        expect(tokenizeShellString('ls | grep foo')).toEqual([
            ['ls'],
            ['grep', 'foo'],
        ]);
    });

    it('handles single-quoted strings', () => {
        expect(tokenizeShellString(`echo 'hello world'`)).toEqual([['echo', 'hello world']]);
    });

    it('handles double-quoted strings', () => {
        expect(tokenizeShellString('echo "hello world"')).toEqual([['echo', 'hello world']]);
    });

    it('handles backslash escaping', () => {
        expect(tokenizeShellString('echo a\\ b')).toEqual([['echo', 'a b']]);
    });

    it('handles double-quote with escaped dollar', () => {
        expect(tokenizeShellString('echo "a\\$b"')).toEqual([['echo', 'a$b']]);
    });

    it('ignores empty commands', () => {
        expect(tokenizeShellString(';;')).toEqual([]);
    });

    it('trims whitespace around commands', () => {
        expect(tokenizeShellString('  ls   -la  ')).toEqual([['ls', '-la']]);
    });
});

describe('tokenizePowerShellString', () => {
    it('splits on && and |', () => {
        expect(tokenizePowerShellString('Get-Process && Stop-Service foo')).toEqual([
            ['Get-Process'],
            ['Stop-Service', 'foo'],
        ]);
    });

    it('uses backtick to escape the next character', () => {
        // The backtick is consumed; only the escaped char is kept.
        expect(tokenizePowerShellString('Write-Output `hello')).toEqual([
            ['Write-Output', 'hello'],
        ]);
    });

    it('escapes a space with backtick', () => {
        expect(tokenizePowerShellString('Write-Output ` hello')).toEqual([
            ['Write-Output', ' hello'],
        ]);
    });

    it('respects both single and double quotes', () => {
        expect(tokenizePowerShellString(`Write-Output "hello world"`)).toEqual([
            ['Write-Output', 'hello world'],
        ]);
    });
});

describe('tokenizeCmdString', () => {
    it('splits on &', () => {
        expect(tokenizeCmdString('dir & echo done')).toEqual([['dir'], ['echo', 'done']]);
    });

    it('uses ^ for escaping', () => {
        expect(tokenizeCmdString('echo a^ b')).toEqual([['echo', 'a b']]);
    });

    it('respects double quotes', () => {
        expect(tokenizeCmdString('echo "hello world"')).toEqual([['echo', 'hello world']]);
    });
});

describe('parseCommand', () => {
    it('returns [argv] for non-shell-wrapped commands', () => {
        expect(parseCommand(['ls', '-la'])).toEqual([['ls', '-la']]);
    });

    it('decomposes bash -c', () => {
        expect(parseCommand(['bash', '-c', 'ls && cat foo'])).toEqual([
            ['ls'],
            ['cat', 'foo'],
        ]);
    });

    it('decomposes powershell -EncodedCommand', () => {
        const encoded = Buffer.from('Get-Process && Stop-Service foo', 'utf16le').toString(
            'base64',
        );
        const out = parseCommand(['pwsh', '-NoProfile', '-EncodedCommand', encoded]);
        expect(out).toEqual([
            ['Get-Process'],
            ['Stop-Service', 'foo'],
        ]);
    });
});
