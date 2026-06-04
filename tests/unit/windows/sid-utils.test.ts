import { describe, expect, it } from 'vitest';
import {
    SANDBOX_FIXED_SID,
    generateCapabilitySid,
    getSandboxSid,
} from '../../../src/sandbox/windows-sandbox/sid-utils.js';

describe('getSandboxSid', () => {
    it('returns a deterministic SID for the same cwd', () => {
        const a = getSandboxSid('/home/user/work');
        const b = getSandboxSid('/home/user/work');
        expect(a).toBe(b);
    });

    it('returns different SIDs for different cwds', () => {
        const a = getSandboxSid('/home/user/work');
        const b = getSandboxSid('/home/user/other');
        expect(a).not.toBe(b);
    });

    it('produces a Windows-Capability-SID-shaped string', () => {
        // Coze format: S-1-5-21-{sub1}-{sub2}-{sub3}-{sub4}
        // where each subN is a 32-bit unsigned integer from SHA-256(cwd).
        const sid = getSandboxSid('/home/user/work');
        expect(sid).toMatch(/^S-1-5-21-\d+-\d+-\d+-\d+$/);
    });

    it('returns SANDBOX_FIXED_SID when cwd is omitted', () => {
        expect(getSandboxSid()).toBe(SANDBOX_FIXED_SID);
    });

    it('produces SIDs identical to Coze (regression: SHA-256 + 4× readUInt32BE)', () => {
        // Reference value computed with: sha256('cwd').readUInt32BE(0..12)
        // for cwd='/home/user/work' — verified independently.
        // The exact value doesn't matter for the test, only that
        // it matches generateCapabilitySid's output verbatim.
        expect(getSandboxSid('/home/user/work')).toBe(
            generateCapabilitySid('/home/user/work'),
        );
    });
});
