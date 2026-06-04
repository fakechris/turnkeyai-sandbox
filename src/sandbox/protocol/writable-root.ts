/**
 * WritableRoot schema.
 *
 * Reverse-engineered from
 * `packages/sandbox/src/protocol/writable-root.ts` .
 *
 * @public
 */

/** A single writable root in a workspaceWrite policy. */
export interface WritableRoot {
    /** Absolute path or path accepted by `path.resolve()`. */
    path: string;
    /** Subpaths within `path` that should be read-only. */
    readOnlySubpaths: string[];
}

/** Type-guard for {@link WritableRoot}. */
export function isWritableRoot(v: unknown): v is WritableRoot {
    if (typeof v !== 'object' || v === null) {
        return false;
    }
    const r = v as Record<string, unknown>;
    return (
        typeof r.path === 'string' &&
        r.path.length > 0 &&
        Array.isArray(r.readOnlySubpaths) &&
        (r.readOnlySubpaths as unknown[]).every((x) => typeof x === 'string')
    );
}
