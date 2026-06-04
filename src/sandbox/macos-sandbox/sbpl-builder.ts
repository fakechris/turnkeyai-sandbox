/**
 * macOS SBPL profile builder.
 *
 * Reverse-engineered from
 * `packages/sandbox/src/macos-sandbox/sbpl-builder.ts`
 * .
 *
 * This is the single source of truth for what the macOS sandbox actually
 * allows. The output is a self-contained SBPL string suitable for passing
 * to `sandbox -p '<profile>' -- <cmd>`.
 *
 * Key safety features:
 * - `(deny default)` first; every allow is explicit
 * - `(allow file-write*)` then `(deny file-write*)` per hardcoded path —
 *   "deny after allow" per PLANNING §14.11
 * - Ancestor-directory deny-unlink guard for hardcoded-deny parents
 *   (PLANNING §14.7) to prevent deletion via parent traversal
 * - Network: deny all OR allow only loopback + proxy ports
 *
 * @public
 */

import { realpathSync } from 'node:fs';
import { dirname, resolve as pathResolve } from 'node:path';
import { homedir } from 'node:os';
import type { SandboxPolicy } from '../protocol/sandbox-policy.js';
import { getEffectiveReadableRoots, getEffectiveWritableRoots, getParentDirectories, shouldIncludePlatformDefaults } from '../sandboxing/filesystem-policy.js';
import { HARDCODED_DENY_PATHS } from '../sandboxing/hardcoded-deny.js';
import { getProxyPorts } from '../network/proxy-env.js';
import { MACOS_RESTRICTED_PLATFORM_DEFAULTS_SBPL } from './restricted-platform-defaults.js';

/** Builder options. */
export interface SbplBuildOptions {
    homeDir?: string;
    cwd?: string;
    /** Path-resolver; defaults to realpathSync with a path.resolve fallback. */
    resolvePath?: (p: string) => string;
    /** Optional logTag to inject as `;; sandbox-tag: ...` for log-stream correlation. */
    logTag?: string;
}

/** Build a complete SBPL profile string from the given SandboxPolicy. */
export function buildSbplProfile(policy: SandboxPolicy, options: SbplBuildOptions = {}): string {
    const homeDir = options.homeDir ?? homedir();
    const cwd = options.cwd ?? process.cwd();
    const resolve = options.resolvePath ?? resolveRealpath;
    const lines: string[] = [];
    if (options.logTag) {
        lines.push(`;; sandbox-tag: ${options.logTag}`);
    }
    lines.push('(version 1)');
    lines.push('(deny default)');
    lines.push('(allow process*)');
    lines.push('(allow sysctl-read)');
    lines.push('(allow mach-lookup)');
    const fsPolicy = policy.filesystem;
    if (fsPolicy.mode === 'dangerFullAccess') {
        lines.push('(allow default)');
        return lines.join('\n');
    }
    if (shouldIncludePlatformDefaults(fsPolicy)) {
        lines.push(MACOS_RESTRICTED_PLATFORM_DEFAULTS_SBPL);
    }
    appendReadableRootRules(lines, fsPolicy, cwd, resolve);
    appendWritableRootRules(lines, fsPolicy, resolve);
    // Hardcoded deny + ancestor-dir deny-unlink
    const denyAbsPaths = resolveHardcodedDenyPaths(homeDir, cwd, resolve);
    for (const absPath of denyAbsPaths) {
        lines.push(`(deny file-write* (subpath ${sbplQuote(absPath)}))`);
        const parentDir = dirname(absPath);
        lines.push(
            [
                '(deny file-write*',
                '  (require-all',
                '    (vnode-type DIRECTORY)',
                `    (literal ${sbplQuote(parentDir)})`,
                `    (require-not (regex #"^${escapeRegex(parentDir)}/[^/]"))))`,
            ].join('\n'),
        );
    }
    appendNetworkRules(lines, policy);
    return lines.join('\n');
}

/** Realpath with a path.resolve fallback (for non-existent targets). */
export function resolveRealpath(p: string): string {
    try {
        return realpathSync(p);
    } catch {
        return pathResolve(p);
    }
}

function resolveHardcodedDenyPaths(homeDir: string, cwd: string, resolve: (p: string) => string): string[] {
    const result: string[] = [];
    const seen = new Set<string>();
    for (const deny of HARDCODED_DENY_PATHS) {
        const fromHome = resolve(pathResolve(homeDir, deny));
        if (!seen.has(fromHome)) {
            seen.add(fromHome);
            result.push(fromHome);
        }
        const fromCwd = resolve(pathResolve(cwd, deny));
        if (!seen.has(fromCwd)) {
            seen.add(fromCwd);
            result.push(fromCwd);
        }
    }
    return result;
}

function appendReadableRootRules(
    lines: string[],
    fsPolicy: SandboxPolicy['filesystem'],
    cwd: string,
    resolve: (p: string) => string,
): void {
    const readableRoots = getEffectiveReadableRoots(fsPolicy, 'darwin', cwd).map((p) => resolve(p));
    for (const parentDir of getParentDirectories(readableRoots)) {
        lines.push(
            `(allow file-read-metadata file-test-existence (path-ancestors ${sbplQuote(parentDir)}))`,
        );
    }
    for (const readable of readableRoots) {
        const resolved = resolve(readable);
        lines.push(`(allow file-read* (subpath ${sbplQuote(resolved)}))`);
    }
}

function appendWritableRootRules(
    lines: string[],
    fsPolicy: SandboxPolicy['filesystem'],
    resolve: (p: string) => string,
): void {
    const writableRoots = getEffectiveWritableRoots(fsPolicy, 'darwin');
    const writableRootPaths = writableRoots.map((r) => resolve(r.path));
    const readOnlySubpaths = writableRoots.flatMap((r) =>
        r.readOnlySubpaths.map((sub) => resolve(pathResolve(r.path, sub))),
    );
    for (const parentDir of getParentDirectories([...writableRootPaths, ...readOnlySubpaths])) {
        lines.push(
            `(allow file-read-metadata file-test-existence (path-ancestors ${sbplQuote(parentDir)}))`,
        );
    }
    for (const writableRoot of writableRoots) {
        const resolvedRoot = resolve(writableRoot.path);
        lines.push(`(allow file-write* (subpath ${sbplQuote(resolvedRoot)}))`);
        for (const subpath of writableRoot.readOnlySubpaths) {
            const resolvedSubpath = resolve(pathResolve(resolvedRoot, subpath));
            lines.push(`(deny file-write* (subpath ${sbplQuote(resolvedSubpath)}))`);
        }
    }
}

function appendNetworkRules(lines: string[], policy: SandboxPolicy): void {
    const { httpPort, socksPort } = getProxyPorts(policy.network);
    const proxyPorts = [httpPort, socksPort].filter((p): p is number => typeof p === 'number');
    if (policy.network.mode === 'open') {
        lines.push('(allow network-outbound)');
        lines.push('(allow network-inbound)');
        return;
    }
    if (proxyPorts.length > 0) {
        lines.push('; restricted network: allow only loopback proxy traffic');
        lines.push('(allow network-bind (local ip "127.0.0.1:*"))');
        lines.push('(allow network-inbound (local ip "127.0.0.1:*"))');
        lines.push('(allow network-outbound (remote ip "127.0.0.1:*"))');
        lines.push('(allow network-outbound (remote ip "::1:*"))');
        for (const port of proxyPorts) {
            lines.push(`(allow network-outbound (remote ip "127.0.0.1:${port}"))`);
            lines.push(`(allow network-outbound (remote ip "::1:${port}"))`);
        }
        return;
    }
    lines.push('(deny network*)');
}

/** Quote a path for use in an SBPL S-expression. */
export function sbplQuote(s: string): string {
    return `"${s.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

/** Escape a string for use in an SBPL regex literal. */
export function escapeRegex(s: string): string {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
