/**
 * argv-quote helpers. Reverse-engineered from
 * `packages/sandbox/src/util/argv-quote.ts` .
 *
 * intentionally does *not* expose a single `quote()` helper because the
 * quoting rules differ by domain:
 *   - POSIX shell: single-quote wrap, escape embedded `'` as `'\''`
 *   - Windows cmd: `"` wrap, double up backslashes before `"`, leave `\` before other chars alone
 *
 * @public
 */

/** POSIX-safe characters (i.e. characters that don't need quoting). */
const POSIX_SAFE_RE = /^[A-Za-z0-9_\-.,:/=@%]+$/;

/**
 * Quote a single argument for safe use as a POSIX shell word.
 *
 * Empty string and any character outside POSIX_SAFE_RE triggers single-quote
 * wrap with `'\''` escape. Identical to the implementation.
 *
 * @example argvQuotePosix("hello world")  // "'hello world'"
 * @example argvQuotePosix("a'b")          // "'a'\\''b'"
 * @public
 */
export function argvQuotePosix(arg: string): string {
    if (arg.length === 0) {
        return "''";
    }
    if (POSIX_SAFE_RE.test(arg)) {
        return arg;
    }
    return `'${arg.replace(/'/g, `'\\''`)}'`;
}

/**
 * Join an argv list into a single POSIX shell string, with each element
 * individually quoted.
 * @public
 */
export function argvQuoteJoinPosix(argv: readonly string[]): string {
    return argv.map(argvQuotePosix).join(' ');
}

/**
 * Quote a single argument for safe use as a Windows `cmd.exe` argument.
 *
 * MSVC rules: backslashes are doubled only when followed by `"` or the end of
 * string. Other backslashes are passed through unchanged. The whole arg is
 * then wrapped in `"`.
 *
 * @example argvQuoteWindows('a"b')  // '"a\\"b"'
 * @public
 */
export function argvQuoteWindows(arg: string): string {
    if (arg.length === 0) {
        return '""';
    }
    // Per MSVC parsing rules:
    // 1. Count trailing backslashes (only when followed by `"` or end-of-string).
    // 2. Escape every `"` by a backslash.
    // 3. Double all backslashes that immediately precede a `"` or end of string.
    let escaped = '';
    let backslashes = 0;
    for (const ch of arg) {
        if (ch === '\\') {
            backslashes++;
            escaped += '\\';
        } else if (ch === '"') {
            // Each backslash before a quote gets doubled.
            escaped += '\\'.repeat(backslashes) + '\\"';
            backslashes = 0;
        } else {
            escaped += ch;
            backslashes = 0;
        }
    }
    // Trailing backslashes (those not before a quote) also get doubled when
    // the argument will be wrapped in quotes (so the shell doesn't eat them).
    escaped += '\\'.repeat(backslashes);
    return `"${escaped}"`;
}

/**
 * Join an argv list into a single Windows `cmd.exe` command line.
 * @public
 */
export function argvQuoteJoinWindows(argv: readonly string[]): string {
    return argv.map(argvQuoteWindows).join(' ');
}
