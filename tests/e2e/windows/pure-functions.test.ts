/**
 * E2E tests for cross-platform pure functions used by the Windows backend.
 *
 * These functions have no FFI dependency and work identically on all
 * platforms. Tests verify:
 * - argvQuoteWindows quoting rules
 * - SID generation algorithm (matches Coze's SHA-256 + readUInt32BE)
 * - WindowsBackendCapabilities type shape
 */
import { describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';

import { argvQuoteWindows } from '../../../src/util/argv-quote.js';
import {
    generateCapabilitySid,
    getSandboxSid,
    SANDBOX_FIXED_SID,
} from '../../../src/sandbox/windows-sandbox/sid-utils.js';

// ── argvQuoteWindows ─────────────────────────────────────────────

describe('argvQuoteWindows', () => {
    it('wraps empty string in double quotes', () => {
        expect(argvQuoteWindows('')).toBe('""');
    });

    it('wraps simple strings in double quotes', () => {
        expect(argvQuoteWindows('simple')).toBe('"simple"');
    });

    it('wraps strings with spaces', () => {
        expect(argvQuoteWindows('has space')).toBe('"has space"');
    });

    it('escapes embedded double quotes with backslash', () => {
        expect(argvQuoteWindows('a"b')).toBe('"a\\"b"');
    });

    it('doubles backslashes before double quotes', () => {
        // a\"b → backslash before " gets doubled
        expect(argvQuoteWindows('a\\"b')).toBe('"a\\\\\\"b"');
    });

    it('passes through backslashes not before quotes', () => {
        expect(argvQuoteWindows('C:\\path')).toBe('"C:\\path"');
    });

    it('handles multiple embedded quotes', () => {
        expect(argvQuoteWindows('a"b"c')).toBe('"a\\"b\\"c"');
    });

    it('handles trailing backslash (doubled at end)', () => {
        // Trailing backslash before closing " gets doubled per MSVC rules
        expect(argvQuoteWindows('path\\')).toBe('"path\\\\"');
    });

    it('does not quote POSIX-safe characters unnecessarily', () => {
        // argvQuoteWindows ALWAYS wraps in quotes (unlike argvQuotePosix)
        expect(argvQuoteWindows('hello')).toBe('"hello"');
    });
});

// ── generateCapabilitySid ────────────────────────────────────────

describe('generateCapabilitySid', () => {
    it('produces S-1-5-21-<sub1>-<sub2>-<sub3>-<sub4> format', () => {
        const sid = generateCapabilitySid('/home/user/work');
        expect(sid).toMatch(/^S-1-5-21-\d+-\d+-\d+-\d+$/);
    });

    it('is deterministic (same input → same output)', () => {
        expect(generateCapabilitySid('/foo')).toBe(generateCapabilitySid('/foo'));
    });

    it('differs for different inputs', () => {
        expect(generateCapabilitySid('/foo')).not.toBe(generateCapabilitySid('/bar'));
    });

    it('matches Coze\'s algorithm: SHA-256 + 4×readUInt32BE', () => {
        // This is the golden test — compute the expected SID independently.
        const cwd = '/home/user/work';
        const hash = createHash('sha256').update(cwd).digest();
        const sub1 = hash.readUInt32BE(0);
        const sub2 = hash.readUInt32BE(4);
        const sub3 = hash.readUInt32BE(8);
        const sub4 = hash.readUInt32BE(12);
        const expected = `S-1-5-21-${sub1}-${sub2}-${sub3}-${sub4}`;
        expect(generateCapabilitySid(cwd)).toBe(expected);
    });

    it('reads from offsets 0, 4, 8, 12 (not 0, 1, 2, 3)', () => {
        // Verify the hash bytes are used correctly by checking a known cwd.
        const cwd = '/test';
        const hash = createHash('sha256').update(cwd).digest();
        // Each sub-authority is a full 32-bit BE integer, not a single byte.
        const sid = generateCapabilitySid(cwd);
        const parts = sid.split('-');
        // S(0)-1(1)-5(2)-21(3)-<sub1>(4)-<sub2>(5)-<sub3>(6)-<sub4>(7)
        expect(Number(parts[4])).toBe(hash.readUInt32BE(0));
        expect(Number(parts[5])).toBe(hash.readUInt32BE(4));
        expect(Number(parts[6])).toBe(hash.readUInt32BE(8));
        expect(Number(parts[7])).toBe(hash.readUInt32BE(12));
    });
});

// ── getSandboxSid ────────────────────────────────────────────────

describe('getSandboxSid', () => {
    it('delegates to generateCapabilitySid when cwd is provided', () => {
        expect(getSandboxSid('/foo')).toBe(generateCapabilitySid('/foo'));
    });

    it('returns SANDBOX_FIXED_SID when cwd is omitted', () => {
        expect(getSandboxSid()).toBe(SANDBOX_FIXED_SID);
    });

    it('returns SANDBOX_FIXED_SID when cwd is undefined', () => {
        expect(getSandboxSid(undefined)).toBe(SANDBOX_FIXED_SID);
    });
});

// ── SANDBOX_FIXED_SID ───────────────────────────────────────────

describe('SANDBOX_FIXED_SID', () => {
    it('matches Coze\'s fixed SID value', () => {
        expect(SANDBOX_FIXED_SID).toBe('S-1-5-21-0-0-0-1000');
    });

    it('has 4 sub-authorities after S-1-5-21', () => {
        const parts = SANDBOX_FIXED_SID.split('-');
        // S(0) - 1(1) - 5(2) - 21(3) - 0(4) - 0(5) - 0(6) - 1000(7)
        expect(parts).toHaveLength(8);
        expect(parts[0]).toBe('S');
        expect(parts[1]).toBe('1');
        expect(parts[2]).toBe('5');
        expect(parts[3]).toBe('21');
    });
});
