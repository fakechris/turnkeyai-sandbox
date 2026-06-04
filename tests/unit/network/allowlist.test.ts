import { describe, expect, it } from 'vitest';
import {
    getDangerousTlds,
    hostAllowed,
    normalizeAllowedHosts,
} from '../../../src/sandbox/network/allowlist.js';

describe('getDangerousTlds', () => {
    it('returns a non-empty set of common TLDs', () => {
        const tlds = getDangerousTlds();
        expect(tlds.has('com')).toBe(true);
        expect(tlds.has('net')).toBe(true);
        expect(tlds.has('org')).toBe(true);
        expect(tlds.has('io')).toBe(true);
        expect(tlds.has('xyz')).toBe(true);
    });
});

describe('normalizeAllowedHosts', () => {
    it('lowercases and trims valid entries', () => {
        const r = normalizeAllowedHosts(['  Example.COM  ', 'api.x.com']);
        expect(r.normalized).toEqual(['example.com', 'api.x.com']);
        expect(r.rejected).toEqual([]);
    });

    it('rejects empty string', () => {
        const r = normalizeAllowedHosts(['']);
        expect(r.rejected).toEqual([{ host: '', reason: 'empty string' }]);
    });

    it('rejects NUL byte', () => {
        const r = normalizeAllowedHosts(['foo\0bar']);
        expect(r.rejected[0]?.reason).toBe('contains nul byte');
    });

    it('rejects bare *', () => {
        const r = normalizeAllowedHosts(['*']);
        expect(r.rejected[0]?.reason).toMatch(/overly broad/);
    });

    it('rejects bare *.*', () => {
        const r = normalizeAllowedHosts(['*.*']);
        expect(r.rejected[0]?.reason).toMatch(/overly broad/);
    });

    it('rejects TLD-level wildcards for dangerous TLDs', () => {
        for (const tld of ['com', 'net', 'org', 'io', 'cn']) {
            const r = normalizeAllowedHosts([`*.${tld}`]);
            expect(r.rejected[0]?.reason).toMatch(new RegExp(`\\*\\.${tld}.*too broad`));
        }
    });

    it('accepts TLD-level wildcards for non-dangerous TLDs', () => {
        // .test is not in DANGEROUS_TLDS
        const r = normalizeAllowedHosts(['*.test']);
        expect(r.rejected).toEqual([]);
        expect(r.normalized).toEqual(['*.test']);
    });

    it('rejects pure-integer strings (port misuse)', () => {
        const r = normalizeAllowedHosts(['12345']);
        expect(r.rejected[0]?.reason).toMatch(/integer IP or port/);
    });

    it('rejects IPv6 zone-IDs', () => {
        const r = normalizeAllowedHosts(['fe80::1%eth0']);
        expect(r.rejected[0]?.reason).toMatch(/zone-ID/);
    });
});

describe('hostAllowed', () => {
    it('matches exact', () => {
        expect(hostAllowed('example.com', ['example.com'])).toBe(true);
    });

    it('matches case-insensitively', () => {
        expect(hostAllowed('EXAMPLE.com', ['example.com'])).toBe(true);
    });

    it('matches *.subdomain wildcards', () => {
        expect(hostAllowed('foo.example.com', ['*.example.com'])).toBe(true);
        expect(hostAllowed('bar.foo.example.com', ['*.example.com'])).toBe(true);
    });

    it('*.wildcard matches the bare apex', () => {
        expect(hostAllowed('example.com', ['*.example.com'])).toBe(true);
    });

    it('does not match unrelated hosts', () => {
        expect(hostAllowed('evil.com', ['example.com'])).toBe(false);
        expect(hostAllowed('example.com.evil.com', ['*.example.com'])).toBe(false);
    });

    it('returns false for empty allowlist', () => {
        expect(hostAllowed('example.com', [])).toBe(false);
    });
});
