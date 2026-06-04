/**
 * Filesystem policy helpers.
 *
 * Reverse-engineered from
 * `packages/sandbox/src/sandboxing/filesystem-policy.ts` .
 *
 * @public
 */

import { dirname, resolve, sep } from 'node:path';
import type { FileSystemSandboxPolicy, WritableRoot } from '../protocol/filesystem-sandbox-policy.js';
import type { Platform } from '../../types/platform.js';
import { HARDCODED_DENY_PATHS } from './hardcoded-deny.js';

/** Minimal Linux readable roots for "no platform-defaults" mode. */
export const LINUX_MINIMAL_READABLE_ROOTS: readonly string[] = [
    '/bin',
    '/dev',
    '/etc',
    '/lib',
    '/lib64',
    '/opt',
    '/proc',
    '/run',
    '/sbin',
    '/sys',
    '/usr',
    '/var',
];

/** Scratch writable roots on Linux. */
export const LINUX_WRITABLE_SCRATCH_ROOTS: readonly string[] = ['/tmp', '/var/tmp'];

/** Windows variant of the deny list. */
const WINDOWS_DIRECTORY_DENY_PATHS = new Set([
    '.agents',
    '.codex',
    '.config/gcloud',
    '.git',
    '.gnupg',
    '.ssh',
]);

/** Whether the policy should inject platform-default readable/writable roots. */
export function shouldIncludePlatformDefaults(
    fsPolicy: FileSystemSandboxPolicy,
): boolean {
    return fsPolicy.mode !== 'dangerFullAccess' && fsPolicy.includePlatformDefaults !== false;
}

/** Effective readable roots (with dedup). */
export function getEffectiveReadableRoots(
    fsPolicy: FileSystemSandboxPolicy,
    platform: Platform,
    cwd: string,
): string[] {
    const roots: string[] = [cwd, ...fsPolicy.readableRoots, ...fsPolicy.writableRoots.map((r) => r.path)];
    if (platform === 'linux' && shouldIncludePlatformDefaults(fsPolicy)) {
        roots.push(...LINUX_MINIMAL_READABLE_ROOTS);
    }
    return dedupeResolvedPaths(roots);
}

/** Effective writable roots (with readOnlySubpaths and platform scratch). */
export function getEffectiveWritableRoots(
    fsPolicy: FileSystemSandboxPolicy,
    platform: Platform,
): WritableRoot[] {
    const merged = new Map<string, string[]>();
    for (const root of fsPolicy.writableRoots) {
        mergeWritableRoot(merged, root.path, root.readOnlySubpaths);
    }
    if (platform === 'linux' && shouldIncludePlatformDefaults(fsPolicy)) {
        for (const scratchRoot of getLinuxWritableScratchRoots()) {
            mergeWritableRoot(merged, scratchRoot, []);
        }
    }
    return [...merged.entries()].map(([path, readOnlySubpaths]) => ({
        path,
        readOnlySubpaths: [...readOnlySubpaths],
    }));
}

function getLinuxWritableScratchRoots(): string[] {
    const roots = [...LINUX_WRITABLE_SCRATCH_ROOTS];
    const envTmp = process.env.TMPDIR ?? process.env.TEMP ?? process.env.TMP;
    if (envTmp && envTmp.startsWith('/')) {
        roots.push(envTmp);
    }
    return roots;
}

function mergeWritableRoot(merged: Map<string, string[]>, path: string, readOnlySubpaths: string[]): void {
    const existing = merged.get(path) ?? [];
    merged.set(path, [...existing, ...readOnlySubpaths]);
}

/** Absolute paths for every anchored hardcoded-deny entry (home + cwd). */
export function getAnchoredHardcodedDenyPaths(homeDir: string, cwd: string): string[] {
    const result = new Set<string>();
    for (const denyPath of HARDCODED_DENY_PATHS) {
        result.add(resolve(homeDir, denyPath));
        result.add(resolve(cwd, denyPath));
    }
    return [...result];
}

/** All parent directories of the given paths, sorted by depth then alpha. */
export function getParentDirectories(paths: readonly string[]): string[] {
    const parents = new Set<string>();
    for (const targetPath of paths) {
        let current = dirname(targetPath);
        while (current !== '/' && current !== '.' && current !== '') {
            parents.add(current);
            current = dirname(current);
        }
    }
    return [...parents].sort((left, right) => {
        const leftDepth = left.split('/').length;
        const rightDepth = right.split('/').length;
        if (leftDepth === rightDepth) {
            return left.localeCompare(right);
        }
        return leftDepth - rightDepth;
    });
}

/** Is `path` equal to or under one of the given roots? */
export function isPathCoveredByRoots(path: string, roots: readonly string[]): boolean {
    return roots.some((root) => path === root || path.startsWith(`${root}${sep}`));
}

/** Is `path` a Windows-style "directory-like" hardcoded deny? */
export function isDirectoryLikeHardcodedDenyPath(path: string): boolean {
    const normalized = path.replace(/\\/g, '/');
    return WINDOWS_DIRECTORY_DENY_PATHS.has(normalized);
}

/** Resolve each path and dedup. */
export function dedupeResolvedPaths(paths: readonly string[]): string[] {
    const deduped = new Set<string>();
    for (const p of paths) {
        deduped.add(resolve(p));
    }
    return [...deduped];
}
