import { describe, expect, it } from 'vitest';
import { getSandboxSid } from '../../../src/sandbox/windows-sandbox/sid-utils.js';

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

    it('produces a Windows-SID-shaped string', () => {
        const sid = getSandboxSid('/home/user/work');
        expect(sid).toMatch(/^S-1-5-21-\d+-1-[0-9a-f]{4}$/);
    });
});
