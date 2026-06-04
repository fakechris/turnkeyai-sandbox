/**
 * In-memory session-scoped approval store.
 *
 * Reverse-engineered from `packages/sandbox-policy/src/rules/approval-store.ts`
 * .
 *
 * Tracks per-session user decisions (allowed/denied) so a single "yes, allow
 * this once" click does not become a permanent policy bypass.
 *
 * @public
 */

import type { ApprovalDecision } from '../../types/result.js';

/** Key used for argv-based approval entries. */
export type ApprovalKey = readonly string[];

/** Decision we persist. */
export type StoredDecision = Extract<
    ApprovalDecision,
    'approved' | 'approved-for-session' | 'approved-amendment'
>;

/**
 * In-memory session-scoped approval store. One instance is created per
 * `ExecPolicyManager`. Lost on process exit.
 *
 * @public
 */
export class ApprovalStore {
    private readonly decisions = new Map<string, StoredDecision>();

    /** Serialise a key (argv or network tuple) into a stable string. */
    private static serialiseKey(key: ApprovalKey): string {
        return JSON.stringify(key);
    }

    /** Returns true if this argv/key was previously approved for the session. */
    isApprovedForSession(key: ApprovalKey): boolean {
        const k = ApprovalStore.serialiseKey(key);
        const v = this.decisions.get(k);
        return v === 'approved' || v === 'approved-for-session' || v === 'approved-amendment';
    }

    /** Returns the raw stored decision (or undefined if none). */
    get(key: ApprovalKey): StoredDecision | undefined {
        return this.decisions.get(ApprovalStore.serialiseKey(key));
    }

    /** Record a user decision. */
    set(key: ApprovalKey, decision: ApprovalDecision): void {
        if (
            decision === 'approved' ||
            decision === 'approved-for-session' ||
            decision === 'approved-amendment'
        ) {
            this.decisions.set(ApprovalStore.serialiseKey(key), decision);
        }
        // 'denied' is intentionally not persisted as a per-session memo to
        // mirror 's design: a denial expires with the current decision,
        // so the user is re-prompted on the next invocation.
    }

    /** Clear all session approvals. */
    clear(): void {
        this.decisions.clear();
    }

    /** Number of approvals currently stored (for diagnostics). */
    get size(): number {
        return this.decisions.size;
    }
}
