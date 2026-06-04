/**
 * Shell-command argv parser.
 *
 * Reverse-engineered from
 * `packages/sandbox-policy/src/command/parser.ts` .
 *
 * Public surface:
 * - {@link getShellWrapInfo} — recognise shell wrappers (`bash -c`, `pwsh -EncodedCommand`, …)
 * - {@link isShellWrapped} — convenience boolean
 * - {@link parseCommand} — split shell string into individual command argvs
 * - {@link tokenizeShellString} / {@link tokenizePowerShellString} / {@link tokenizeCmdString} — low-level tokenizers
 *
 * @public
 */

import { normalizeCommandName } from './common.js';

/** Recognised POSIX shell basenames. */
const POSIX_SHELL_BASENAMES = new Set(['bash', 'sh', 'zsh']);

/** Recognised PowerShell basenames. */
const POWERSHELL_BASENAMES = new Set(['powershell', 'pwsh']);

/** Recognised cmd.exe basenames. */
const CMD_SHELL_BASENAMES = new Set(['cmd']);

/** Information about a shell-wrapped argv. */
export interface ShellWrapInfo {
    dialect: 'posix' | 'powershell' | 'cmd';
    /** Index in `argv` at which the actual command string lives. */
    commandIndex: number;
    /** For PowerShell `-EncodedCommand`, the string is base64-decoded UTF-16LE. */
    encoded?: boolean;
}

/**
 * Decode a PowerShell `-EncodedCommand` value.
 * Returns the input on decode failure (mirrors 's try/catch).
 */
function decodePowerShellEncodedCommand(encodedCommand: string): string {
    try {
        return Buffer.from(encodedCommand, 'base64').toString('utf16le');
    } catch {
        return encodedCommand;
    }
}

/**
 * Inspect an argv to detect a shell wrapper like `bash -c "..."` or
 * `pwsh -EncodedCommand ...`. Returns `undefined` if the argv is not a
 * shell-wrapped command.
 *
 * @public
 */
export function getShellWrapInfo(argv: readonly string[]): ShellWrapInfo | undefined {
    if (argv.length < 3) {
        return undefined;
    }
    const commandName = normalizeCommandName(argv[0] ?? '');
    if (POSIX_SHELL_BASENAMES.has(commandName)) {
        const flag = argv[1];
        if (flag === '-c' || flag === '-lc') {
            return { dialect: 'posix', commandIndex: 2 };
        }
        return undefined;
    }
    if (POWERSHELL_BASENAMES.has(commandName)) {
        const firstFlag = argv[1];
        const secondFlag = argv[2];
        if (firstFlag === '-Command' || firstFlag === '-c') {
            return { dialect: 'powershell', commandIndex: 2 };
        }
        if (firstFlag === '-NoProfile' && (secondFlag === '-Command' || secondFlag === '-c')) {
            return { dialect: 'powershell', commandIndex: 3 };
        }
        if (firstFlag === '-EncodedCommand' || firstFlag === '-ec') {
            return { dialect: 'powershell', commandIndex: 2, encoded: true };
        }
        if (firstFlag === '-NoProfile' && (secondFlag === '-EncodedCommand' || secondFlag === '-ec')) {
            return { dialect: 'powershell', commandIndex: 3, encoded: true };
        }
        return undefined;
    }
    if (CMD_SHELL_BASENAMES.has(commandName)) {
        const flag = argv[1]?.toLowerCase();
        if (flag === '/c' || flag === '/k') {
            return { dialect: 'cmd', commandIndex: 2 };
        }
    }
    return undefined;
}

/**
 * Returns true if argv represents a shell-wrapped command
 * (e.g. `["bash", "-c", "ls && cat foo"]`).
 * @public
 */
export function isShellWrapped(argv: readonly string[]): boolean {
    return getShellWrapInfo(argv) !== undefined;
}

/**
 * Parse a command argv into individual command argv arrays.
 *
 * If the argv is shell-wrapped, the shell string is tokenized into individual
 * commands. Otherwise, returns `[argv]`.
 *
 * @example
 * parseCommand(["bash", "-c", "ls && cat foo"]) // [["ls"], ["cat", "foo"]]
 * parseCommand(["ls", "-la"])                   // [["ls", "-la"]]
 *
 * @public
 */
export function parseCommand(argv: readonly string[]): readonly (readonly string[])[] {
    const shellWrapInfo = getShellWrapInfo(argv);
    if (shellWrapInfo) {
        const rawShellStr = argv.slice(shellWrapInfo.commandIndex).join(' ');
        const shellStr =
            shellWrapInfo.dialect === 'powershell' && shellWrapInfo.encoded
                ? decodePowerShellEncodedCommand(rawShellStr)
                : rawShellStr;
        switch (shellWrapInfo.dialect) {
            case 'powershell':
                return tokenizePowerShellString(shellStr);
            case 'cmd':
                return tokenizeCmdString(shellStr);
            default:
                return tokenizeShellString(shellStr);
        }
    }
    return [argv];
}

/**
 * Tokenize a POSIX shell string into individual command argv arrays.
 *
 * Handles:
 * - `&&`, `||`, `;` as command separators
 * - `|` pipe (each pipe segment is its own command)
 * - Single-quotes, double-quotes, backslash escaping
 * - Consecutive whitespace trimming
 * - Empty commands are ignored
 *
 * @public
 */
export function tokenizeShellString(shellStr: string): string[][] {
    const commands: string[][] = [];
    let currentArgs: string[] = [];
    let currentToken = '';
    let inSingleQuote = false;
    let inDoubleQuote = false;
    let escaped = false;
    const flushToken = (): void => {
        if (currentToken.length > 0) {
            currentArgs.push(currentToken);
            currentToken = '';
        }
    };
    const flushCommand = (): void => {
        flushToken();
        if (currentArgs.length > 0) {
            commands.push(currentArgs);
            currentArgs = [];
        }
    };
    for (let i = 0; i < shellStr.length; i++) {
        const ch = shellStr[i];
        if (escaped) {
            currentToken += ch;
            escaped = false;
            continue;
        }
        if (ch === '\\' && !inSingleQuote) {
            if (inDoubleQuote) {
                // In double quotes, backslash only escapes specific characters.
                const next = shellStr[i + 1];
                if (next === '"' || next === '\\' || next === '$' || next === '`') {
                    escaped = true;
                    continue;
                }
                currentToken += ch;
            } else {
                escaped = true;
            }
            continue;
        }
        if (ch === "'" && !inDoubleQuote) {
            inSingleQuote = !inSingleQuote;
            continue;
        }
        if (ch === '"' && !inSingleQuote) {
            inDoubleQuote = !inDoubleQuote;
            continue;
        }
        if (inSingleQuote || inDoubleQuote) {
            currentToken += ch;
            continue;
        }
        // Outside quotes — handle separators and whitespace
        if (ch === '&' && shellStr[i + 1] === '&') {
            flushCommand();
            i++;
            continue;
        }
        if (ch === '|' && shellStr[i + 1] === '|') {
            flushCommand();
            i++;
            continue;
        }
        if (ch === '|') {
            flushCommand();
            continue;
        }
        if (ch === ';') {
            flushCommand();
            continue;
        }
        if (ch === ' ' || ch === '\t') {
            flushToken();
            continue;
        }
        currentToken += ch;
    }
    flushCommand();
    return commands;
}

/**
 * Tokenize a PowerShell command string.
 *
 * Differs from POSIX in that PowerShell uses `` ` `` for line-continuation /
 * escaping (NOT a backslash), single *and* double quotes both open/close
 * tokenisation, and `;` is a separator (not a `;` continuation).
 *
 * @public
 */
export function tokenizePowerShellString(shellStr: string): string[][] {
    const commands: string[][] = [];
    let currentArgs: string[] = [];
    let currentToken = '';
    let inSingleQuote = false;
    let inDoubleQuote = false;
    let escaped = false;
    const flushToken = (): void => {
        if (currentToken.length > 0) {
            currentArgs.push(currentToken);
            currentToken = '';
        }
    };
    const flushCommand = (): void => {
        flushToken();
        if (currentArgs.length > 0) {
            commands.push(currentArgs);
            currentArgs = [];
        }
    };
    for (let i = 0; i < shellStr.length; i++) {
        const ch = shellStr[i];
        if (escaped) {
            currentToken += ch;
            escaped = false;
            continue;
        }
        if (ch === '`' && !inSingleQuote) {
            escaped = true;
            continue;
        }
        if (ch === "'" && !inDoubleQuote) {
            inSingleQuote = !inSingleQuote;
            continue;
        }
        if (ch === '"' && !inSingleQuote) {
            inDoubleQuote = !inDoubleQuote;
            continue;
        }
        if (inSingleQuote || inDoubleQuote) {
            currentToken += ch;
            continue;
        }
        if (ch === '&' && shellStr[i + 1] === '&') {
            flushCommand();
            i++;
            continue;
        }
        if (ch === '|' && shellStr[i + 1] === '|') {
            flushCommand();
            i++;
            continue;
        }
        if (ch === '|' || ch === ';') {
            flushCommand();
            continue;
        }
        if (ch === ' ' || ch === '\t') {
            flushToken();
            continue;
        }
        currentToken += ch;
    }
    flushCommand();
    return commands;
}

/**
 * Tokenize a Windows `cmd.exe` command string.
 *
 * No single-quote concept; `"` toggles; `^` escapes; `&` and `|` and
 * `&&`/`||` are separators (same as POSIX).
 *
 * @public
 */
export function tokenizeCmdString(shellStr: string): string[][] {
    const commands: string[][] = [];
    let currentArgs: string[] = [];
    let currentToken = '';
    let inDoubleQuote = false;
    let escaped = false;
    const flushToken = (): void => {
        if (currentToken.length > 0) {
            currentArgs.push(currentToken);
            currentToken = '';
        }
    };
    const flushCommand = (): void => {
        flushToken();
        if (currentArgs.length > 0) {
            commands.push(currentArgs);
            currentArgs = [];
        }
    };
    for (let i = 0; i < shellStr.length; i++) {
        const ch = shellStr[i];
        if (escaped) {
            currentToken += ch;
            escaped = false;
            continue;
        }
        if (ch === '^') {
            escaped = true;
            continue;
        }
        if (ch === '"') {
            inDoubleQuote = !inDoubleQuote;
            continue;
        }
        if (inDoubleQuote) {
            currentToken += ch;
            continue;
        }
        if (ch === '&' && shellStr[i + 1] === '&') {
            flushCommand();
            i++;
            continue;
        }
        if (ch === '|' && shellStr[i + 1] === '|') {
            flushCommand();
            i++;
            continue;
        }
        if (ch === '&' || ch === '|') {
            flushCommand();
            continue;
        }
        if (ch === ' ' || ch === '\t') {
            flushToken();
            continue;
        }
        currentToken += ch;
    }
    flushCommand();
    return commands;
}
