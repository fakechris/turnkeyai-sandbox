import { describe, expect, it } from 'vitest';
import {
    EXECUTABLE_EXTENSION_RE,
    getCommandBasename,
    normalizeCommandName,
} from '../../../src/policy/command/common.js';

describe('EXECUTABLE_EXTENSION_RE', () => {
    it('matches common executable extensions', () => {
        expect(EXECUTABLE_EXTENSION_RE.test('foo.exe')).toBe(true);
        expect(EXECUTABLE_EXTENSION_RE.test('foo.cmd')).toBe(true);
        expect(EXECUTABLE_EXTENSION_RE.test('foo.bat')).toBe(true);
        expect(EXECUTABLE_EXTENSION_RE.test('foo.ps1')).toBe(true);
        expect(EXECUTABLE_EXTENSION_RE.test('FOO.EXE')).toBe(true);
    });

    it('does not match other extensions or extensionless names', () => {
        expect(EXECUTABLE_EXTENSION_RE.test('foo')).toBe(false);
        expect(EXECUTABLE_EXTENSION_RE.test('foo.sh')).toBe(false);
        expect(EXECUTABLE_EXTENSION_RE.test('foo.txt')).toBe(false);
    });
});

describe('getCommandBasename', () => {
    it('returns the last path segment for unix paths', () => {
        expect(getCommandBasename('/usr/bin/git')).toBe('git');
        expect(getCommandBasename('node')).toBe('node');
    });

    it('handles Windows-style backslash paths', () => {
        expect(getCommandBasename('C:\\Program Files\\Git\\bin\\git.exe')).toBe('git.exe');
    });

    it('handles mixed separators', () => {
        expect(getCommandBasename('C:/Program Files/Git/bin/git.exe')).toBe('git.exe');
    });
});

describe('normalizeCommandName', () => {
    it('lowercases and strips the .exe extension', () => {
        expect(normalizeCommandName('/usr/bin/git.exe')).toBe('git');
        expect(normalizeCommandName('NODE.EXE')).toBe('node');
    });

    it('handles command names without extension', () => {
        expect(normalizeCommandName('node')).toBe('node');
    });
});
