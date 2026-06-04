/**
 * Shared hardcoded deny paths.
 *
 * Reverse-engineered from
 * `packages/sandbox/src/sandboxing/hardcoded-deny.ts` .
 *
 * These paths must never be writable by sandboxed processes. Paths are
 * interpreted as relative to both `homeDir` and `cwd` and the compile step
 * refuses any writable root that overlaps an absolute resolved deny path.
 *
 * @public
 */

import { resolve, sep } from 'node:path';

/** Paths that may never be written, relative to home or cwd. */
export const HARDCODED_DENY_PATHS: readonly string[] = [
    '.git',
    '.ssh',
    '.codex',
    '.agents',
    '.gnupg',
    '.aws/credentials',
    '.config/gcloud',
    '.kube/config',
];

/**
 * Resolve a deny-relative path against both `homeDir` and `cwd`, returning
 * the absolute resolved variants.
 *
 * @public
 */
export function resolveAnchors(denyRelative: string, homeDir: string, cwd: string): string[] {
    const anchors: string[] = [];
    anchors.push(resolve(homeDir, denyRelative));
    const fromCwd = resolve(cwd, denyRelative);
    if (fromCwd !== anchors[0]) {
        anchors.push(fromCwd);
    }
    return anchors;
}

/**
 * Check whether any of the given writable roots overlap with a hardcoded
 * deny path. Returns the list of deny paths that are covered by at least
 * one writable root.
 *
 * Reverse-engineered from.
 *
 * @public
 */
export function checkHardcodedDenyOverlap(
    writableRoots: readonly { path: string }[],
    homeDir: string,
    cwd: string,
): string[] {
    const overlaps: string[] = [];
    const resolvedRoots = writableRoots.map((wr) => resolve(wr.path));
    for (const deny of HARDCODED_DENY_PATHS) {
        const anchors = resolveAnchors(deny, homeDir, cwd);
        for (const absAnchor of anchors) {
            const covered = resolvedRoots.some(
                (root) => absAnchor === root || absAnchor.startsWith(root + sep),
            );
            if (covered) {
                overlaps.push(deny);
                break;
            }
        }
    }
    return overlaps;
}

/**
 * Check whether any of the given paths hit a hardcoded deny path.
 * Returns the subset of deny entries that are matched.
 *
 * Reverse-engineered from.
 *
 * @public
 */
export function checkPathAgainstDenyList(
    paths: readonly string[],
    homeDir: string,
    cwd: string,
): string[] {
    const hits: string[] = [];
    for (const deny of HARDCODED_DENY_PATHS) {
        const anchors = resolveAnchors(deny, homeDir, cwd);
        for (const inputPath of paths) {
            const resolved = resolve(inputPath);
            const matched = anchors.some(
                (anchor) => resolved === anchor || resolved.startsWith(anchor + sep),
            );
            if (matched) {
                hits.push(deny);
                break;
            }
        }
    }
    return hits;
}
