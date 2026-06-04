import { accessSync, constants as fsConstants } from 'node:fs';
import { basename } from 'node:path';
import { getPlatform } from './platform.js';
import type { Platform } from '../types/platform.js';

/**
 * Shell detection / shell-wrapping helpers. Reverse-engineered from
 * `packages/sandbox/src/util/shell.ts` .
 *
 * @public
 */

const POSIX_SHELL_CANDIDATES: Readonly<Record<string, 'bash' | 'zsh' | 'sh'>> = {
    zsh: 'zsh',
    bash: 'bash',
    sh: 'sh',
};

interface ShellCandidate {
    type: 'bash' | 'zsh' | 'sh';
    paths: string[];
}

const DARWIN_FALLBACK_ORDER: readonly ShellCandidate[] = [
    { type: 'zsh', paths: ['/bin/zsh', '/usr/bin/zsh'] },
    { type: 'bash', paths: ['/bin/bash', '/usr/bin/bash'] },
    { type: 'sh', paths: ['/bin/sh'] },
];

const LINUX_FALLBACK_ORDER: readonly ShellCandidate[] = [
    { type: 'bash', paths: ['/bin/bash', '/usr/bin/bash'] },
    { type: 'zsh', paths: ['/bin/zsh', '/usr/bin/zsh'] },
    { type: 'sh', paths: ['/bin/sh'] },
];

const WINDOWS_POWERSHELL_PATHS: readonly string[] = [
    'C:\\Program Files\\PowerShell\\7\\pwsh.exe',
    'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
];

/** Detected shell info returned by `detectShell`. */
export interface DetectedShell {
    type: 'bash' | 'zsh' | 'sh' | 'powershell' | 'cmd';
    path: string;
}

/**
 * Encode a command for PowerShell's `-EncodedCommand` flag.
 * Reverse-engineered from.
 *
 * PowerShell expects UTF-16LE base64; this is the standard "stealth" path
 * that bypasses quoting issues.
 *
 * @public
 */
export function encodePowerShellCommand(command: string): string {
    return Buffer.from(command, 'utf16le').toString('base64');
}

/** Check whether a path is executable on the current platform. */
function fileExists(p: string): boolean {
    try {
        accessSync(p, fsConstants.X_OK);
        return true;
    } catch {
        return false;
    }
}

/** Try to read the user's preferred shell from `$SHELL`. */
function detectShellFromEnv(): DetectedShell | null {
    const envShell = process.env.SHELL;
    if (!envShell) {
        return null;
    }
    const shellBasename = basename(envShell);
    const shellType = POSIX_SHELL_CANDIDATES[shellBasename];
    if (shellType) {
        return { type: shellType, path: envShell };
    }
    return null;
}

function detectPosixShell(fallbackOrder: readonly ShellCandidate[]): DetectedShell {
    const fromEnv = detectShellFromEnv();
    if (fromEnv) {
        return fromEnv;
    }
    for (const candidate of fallbackOrder) {
        for (const p of candidate.paths) {
            if (fileExists(p)) {
                return { type: candidate.type, path: p };
            }
        }
    }
    return { type: 'sh', path: '/bin/sh' };
}

function detectWindowsShell(): DetectedShell {
    for (const p of WINDOWS_POWERSHELL_PATHS) {
        if (fileExists(p)) {
            return { type: 'powershell', path: p };
        }
    }
    const comSpec = process.env.ComSpec;
    if (comSpec) {
        return { type: 'cmd', path: comSpec };
    }
    return { type: 'cmd', path: 'cmd.exe' };
}

/**
 * Detect the preferred shell for a given platform.
 *
 * - macOS: `$SHELL` → zsh → bash → /bin/sh
 * - Linux: `$SHELL` → bash → zsh → /bin/sh
 * - Windows: PowerShell (known paths) → cmd.exe
 *
 * Reverse-engineered from.
 * @public
 */
export function detectShell(platform?: Platform): DetectedShell {
    const p = platform ?? getPlatform();
    switch (p) {
        case 'darwin':
            return detectPosixShell(DARWIN_FALLBACK_ORDER);
        case 'linux':
            return detectPosixShell(LINUX_FALLBACK_ORDER);
        case 'win32':
            return detectWindowsShell();
        default:
            return detectPosixShell(LINUX_FALLBACK_ORDER);
    }
}

/** Options for {@link toShellArgv}. */
export interface ToShellArgvOptions {
    /** Override the detected shell. */
    shell?: DetectedShell;
    /** Force a login shell flag (`-l` / `-lc`). */
    loginShell?: boolean;
    /** Force an interactive shell flag (`-i` / `-ic` / `-ilc`). */
    interactiveShell?: boolean;
    /** Override the target platform for shell detection. */
    platform?: Platform;
}

/**
 * Convert a freeform command string into a shell-wrapped argv array.
 *
 * Examples:
 * ```
 * toShellArgv("ls -la | grep foo")
 * // macOS → ["/bin/zsh", "-c", "ls -la | grep foo"]
 * // Linux → ["/bin/bash", "-c", "ls -la | grep foo"]
 * // Windows → ["powershell.exe", "-NoProfile", "-EncodedCommand", "<base64>"]
 * ```
 *
 * @public
 */
export function toShellArgv(command: string, options?: ToShellArgvOptions): string[] {
    if (!command) {
        throw new Error('toShellArgv: command must not be empty');
    }
    const shell = options?.shell ?? detectShell(options?.platform);
    const login = options?.loginShell ?? false;
    const interactive = options?.interactiveShell ?? false;
    switch (shell.type) {
        case 'bash':
        case 'zsh':
        case 'sh': {
            const flag =
                interactive && login ? '-ilc'
                : interactive ? '-ic'
                : login ? '-lc'
                : '-c';
            return [shell.path, flag, command];
        }
        case 'powershell':
            return [shell.path, '-NoProfile', '-EncodedCommand', encodePowerShellCommand(command)];
        case 'cmd':
            return [shell.path, '/c', command];
    }
}
