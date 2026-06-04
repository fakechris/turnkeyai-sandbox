/**
 * Common helpers for command classification.
 *
 * Reverse-engineered from
 * `packages/sandbox-policy/src/command/common.ts` ().
 *
 * @public
 */

/** Strips Windows-style executable extensions (`exe`, `cmd`, `bat`, `ps1`). */
export const EXECUTABLE_EXTENSION_RE = /\.(exe|cmd|bat|ps1)$/i;

/**
 * Returns the last path segment of a possibly-windows-style command path.
 *
 * Normalises `\` to `/` for matching before splitting so that `C:\foo\bar.exe`
 * returns `bar.exe`.
 *
 * @public
 */
export function getCommandBasename(command: string): string {
    const normalized = command.replace(/\\/g, '/');
    const segments = normalized.split('/');
    return segments[segments.length - 1] ?? normalized;
}

/**
 * Canonicalise a command name to a comparison-friendly form.
 *
 * - Lowercases the basename
 * - Strips `.exe` / `.cmd` / `.bat` / `.ps1` extension
 *
 * @example normalizeCommandName("/usr/bin/git.exe") // "git"
 * @public
 */
export function normalizeCommandName(command: string): string {
    return getCommandBasename(command).replace(EXECUTABLE_EXTENSION_RE, '').toLowerCase();
}
