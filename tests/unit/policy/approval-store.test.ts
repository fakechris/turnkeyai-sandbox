import { describe, expect, it } from 'vitest';
import { ApprovalStore } from '../../../src/policy/rules/approval-store.js';

describe('ApprovalStore', () => {
    it('starts empty', () => {
        const s = new ApprovalStore();
        expect(s.size).toBe(0);
    });

    it('isApprovedForSession returns true after approved / approved-for-session / approved-amendment', () => {
        const s = new ApprovalStore();
        expect(s.isApprovedForSession(['ls'])).toBe(false);
        s.set(['ls'], 'approved');
        expect(s.isApprovedForSession(['ls'])).toBe(true);
        s.set(['cat'], 'approved-for-session');
        expect(s.isApprovedForSession(['cat'])).toBe(true);
        s.set(['pwd'], 'approved-amendment');
        expect(s.isApprovedForSession(['pwd'])).toBe(true);
    });

    it('does not persist denied as session-approval', () => {
        const s = new ApprovalStore();
        s.set(['rm', '-rf'], 'denied');
        expect(s.isApprovedForSession(['rm', '-rf'])).toBe(false);
        expect(s.get(['rm', '-rf'])).toBeUndefined();
    });

    it('returns the raw stored decision via get', () => {
        const s = new ApprovalStore();
        s.set(['ls'], 'approved-amendment');
        expect(s.get(['ls'])).toBe('approved-amendment');
    });

    it('clear() drops all stored decisions', () => {
        const s = new ApprovalStore();
        s.set(['ls'], 'approved');
        s.set(['cat'], 'approved-for-session');
        s.clear();
        expect(s.size).toBe(0);
        expect(s.isApprovedForSession(['ls'])).toBe(false);
    });

    it('handles complex argv keys', () => {
        const s = new ApprovalStore();
        s.set(['git', 'status', '--porcelain'], 'approved');
        expect(s.isApprovedForSession(['git', 'status', '--porcelain'])).toBe(true);
        expect(s.isApprovedForSession(['git', 'status'])).toBe(false);
    });
});
