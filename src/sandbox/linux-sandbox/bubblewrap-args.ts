/**
 * bubblewrap (bwrap) argv builder.
 *
 * Reverse-engineered from
 * `packages/sandbox/src/linux-sandbox/bubblewrap-args.ts`
 * .
 *
 * Returns the argv slice AFTER `bwrap`, ending with `--` and the original
 * command. 's bwrap always:
 * - starts from an empty rootfs (`--tmpfs /`)
 * - mounts `/dev`, `/proc`, `/tmp`
 * - explicit `--ro-bind` for readable roots, `--bind` for writable roots
 * - overlays hardcoded-deny paths with empty `--tmpfs` when covered by
 *   a mounted root
 * - `--unshare-net` for restricted network
 * - `--die-with-parent --new-session` for safety
 *
 * @public
 */

import { homedir } from 'node:os';
import { resolve as pathResolve } from 'node:path';
import type { SandboxPolicy } from '../protocol/sandbox-policy.js';
import type { UserCommand } from '../protocol/user-command.js';
import {
    getEffectiveReadableRoots,
    getEffectiveWritableRoots,
    getParentDirectories,
    isPathCoveredByRoots,
} from '../sandboxing/filesystem-policy.js';
import { getAnchoredHardcodedDenyPaths } from '../sandboxing/filesystem-policy.js';

/** Builder options. */
export interface BubblewrapBuildOptions {
    homeDir?: string;
    cwd?: string;
}

/** Build the argument array (after `bwrap`) for the given policy + request. */
export function buildBubblewrapArgs(
    req: UserCommand,
    policy: SandboxPolicy,
    options: BubblewrapBuildOptions = {},
): string[] {
    const args: string[] = [];
    const homeDir = options.homeDir ?? homedir();
    const cwd = options.cwd ?? req.cwd ?? process.cwd();
    const fsPolicy = policy.filesystem;
    const netPolicy = policy.network;

    if (fsPolicy.mode === 'dangerFullAccess') {
        // Defensive: should not reach here (SandboxManager should select 'none').
        args.push('--die-with-parent', '--new-session');
        args.push('--', ...req.argv);
        return args;
    }

    // Base bindings
    args.push('--tmpfs', '/');
    args.push('--dev', '/dev');
    args.push('--proc', '/proc');
    args.push('--dir', '/tmp');

    const readableRoots = getEffectiveReadableRoots(fsPolicy, 'linux', cwd);
    const writableRoots = getEffectiveWritableRoots(fsPolicy, 'linux');
    const writableRootPaths = writableRoots.map((r) => pathResolve(r.path));
    const mountedRoots = [...new Set([...readableRoots, ...writableRootPaths])];
    const readOnlySubpaths = writableRoots.flatMap((r) =>
        r.readOnlySubpaths.map((s) => pathResolve(r.path, s)),
    );
    for (const parentDir of getParentDirectories([...mountedRoots, ...readOnlySubpaths])) {
        args.push('--dir', parentDir);
    }

    // Read-only binds
    for (const readable of readableRoots) {
        args.push('--ro-bind', readable, readable);
    }
    // Writable binds
    for (const writableRoot of writableRoots) {
        const writablePath = pathResolve(writableRoot.path);
        args.push('--bind', writablePath, writablePath);
        for (const subpath of writableRoot.readOnlySubpaths) {
            const readOnlySubpath = pathResolve(writablePath, subpath);
            args.push('--ro-bind', readOnlySubpath, readOnlySubpath);
        }
    }
    // Hardcoded-deny: tmpfs-overlay covered paths
    for (const denyPath of getAnchoredHardcodedDenyPaths(homeDir, cwd)) {
        if (isPathCoveredByRoots(denyPath, mountedRoots)) {
            args.push('--dir', denyPath);
            args.push('--tmpfs', denyPath);
        }
    }
    // Network
    if (netPolicy.mode === 'restricted') {
        args.push('--unshare-net');
    }
    // Safety flags
    args.push('--die-with-parent');
    args.push('--new-session');
    // Separator + original command
    args.push('--', ...req.argv);
    return args;
}
