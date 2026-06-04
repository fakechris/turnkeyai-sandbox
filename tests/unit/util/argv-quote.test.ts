import { describe, expect, it } from 'vitest';
import {
    argvQuotePosix,
    argvQuoteWindows,
    argvQuoteJoinPosix,
    argvQuoteJoinWindows,
} from '../../../src/util/argv-quote.js';

describe('argvQuotePosix', () => {
    it('returns the bare string when all characters are POSIX-safe', () => {
        expect(argvQuotePosix('hello')).toBe('hello');
        expect(argvQuotePosix('/usr/local/bin/node')).toBe('/usr/local/bin/node');
        expect(argvQuotePosix('--flag=value')).toBe('--flag=value');
    });

    it("wraps in single quotes when the string contains a space", () => {
        expect(argvQuotePosix('hello world')).toBe("'hello world'");
    });

    it('returns empty-string-safe quote for empty input', () => {
        expect(argvQuotePosix('')).toBe("''");
    });

    it("escapes single quotes via '\\\\''", () => {
        expect(argvQuotePosix("a'b")).toBe(`'a'\\''b'`);
    });

    it('quotes strings with semicolons, ampersands, and pipes', () => {
        expect(argvQuotePosix('a;b&c|d')).toBe("'a;b&c|d'");
    });
});

describe('argvQuoteJoinPosix', () => {
    it('joins with spaces, quoting each element as needed', () => {
        expect(argvQuoteJoinPosix(['ls', '-la', '/tmp dir'])).toBe(`ls -la '/tmp dir'`);
    });
});

describe('argvQuoteWindows', () => {
    it('wraps simple strings in double quotes', () => {
        expect(argvQuoteWindows('hello')).toBe('"hello"');
    });

    it('returns "" for empty input', () => {
        expect(argvQuoteWindows('')).toBe('""');
    });

    it('escapes embedded double quotes by backslash-doubling', () => {
        expect(argvQuoteWindows('a"b')).toBe('"a\\"b"');
    });

    it('leaves a single backslash alone when followed by non-quote', () => {
        expect(argvQuoteWindows('a\\b')).toBe('"a\\b"');
    });

    it('doubles backslashes immediately before a double quote', () => {
        // The single \ is preserved literally; the " is escaped.
        expect(argvQuoteWindows('a\\b"c')).toBe('"a\\b\\"c"');
    });

    it('doubles all backslashes when the entire string is backslashes', () => {
        expect(argvQuoteWindows('\\\\')).toBe('"\\\\\\\\"');
    });
});

describe('argvQuoteJoinWindows', () => {
    it('always wraps each element in double quotes (Windows has no safe-chars rule)', () => {
        expect(argvQuoteJoinWindows(['cmd', '/c', 'echo hi'])).toBe('"cmd" "/c" "echo hi"');
    });
});
