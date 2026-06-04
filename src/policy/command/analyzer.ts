/**
 * Command path-access analyzer.
 *
 * Reverse-engineered from
 * `packages/sandbox-policy/src/command/analyzer.ts` .
 *
 * Given an argv, walk each sub-command and extract the paths it would touch
 * (read/write/delete/create/move). This drives preflight violation prediction
 * and runtime path policy enforcement.
 *
 * @public
 */

import type { CommandClassification, PathAccess, PathAccessKind } from '../../types/result.js';
import { parseCommand } from './parser.js';
import { normalizeCommandName } from './common.js';
import { classifyCommand as classifyCommandForAnalyzer } from './classifier.js';

/** POSIX/PowerShell redirection operators (excluding fd-numbers, handled separately). */
const REDIRECTION_OPERATORS = new Set(['<', '>', '>>']);

/** Matches `<`, `>`, `>>` optionally prefixed with a file descriptor number (`2>`). */
const REDIRECTION_WITH_FD_RE = /^\d*(<|>>?)$/;

function createAccess(
    path: string,
    kind: PathAccessKind,
    command: readonly string[],
): PathAccess {
    return { path, kind, command };
}

/**
 * Collect positional (non-option) args. Stops parsing options after `--`.
 *
 * @internal
 */
function collectNonOptionArgs(args: readonly string[]): string[] {
    const values: string[] = [];
    let endOfOptions = false;
    for (const arg of args) {
        if (!endOfOptions && arg === '--') {
            endOfOptions = true;
            continue;
        }
        if (!endOfOptions && arg.startsWith('-')) {
            continue;
        }
        values.push(arg);
    }
    return values;
}

/**
 * Walk a parsed command argv and return path accesses implied by `<`, `>`,
 * `>>` redirection operators (with optional file-descriptor prefix).
 *
 * @internal
 */
function extractRedirectedPathAccesses(command: readonly string[]): PathAccess[] {
    const accesses: PathAccess[] = [];
    for (let i = 1; i < command.length - 1; i++) {
        const token = command[i] ?? '';
        if (REDIRECTION_OPERATORS.has(token) || REDIRECTION_WITH_FD_RE.test(token)) {
            const next = command[i + 1];
            if (!next) {
                continue;
            }
            const kind: PathAccessKind = token.includes('<') ? 'read' : 'write';
            accesses.push(createAccess(next, kind, command));
        }
    }
    return accesses;
}

function extractPositionalPathAccesses(
    args: readonly string[],
    kind: PathAccessKind,
    command: readonly string[],
): PathAccess[] {
    return collectNonOptionArgs(args).map((path) => createAccess(path, kind, command));
}

function extractCopyLikeAccesses(
    args: readonly string[],
    command: readonly string[],
    sourceKind: PathAccessKind,
    targetKind: PathAccessKind,
): PathAccess[] {
    const pathArgs = collectNonOptionArgs(args);
    if (pathArgs.length < 2) {
        return [];
    }
    return pathArgs.flatMap((path, index) => [
        createAccess(path, index === pathArgs.length - 1 ? targetKind : sourceKind, command),
    ]);
}

function extractFindAccesses(args: readonly string[], command: readonly string[]): PathAccess[] {
    const paths: string[] = [];
    for (const arg of args) {
        if (arg === '--') {
            continue;
        }
        if (arg.startsWith('-') || arg === '(' || arg === ')' || arg === '!' || arg === '-o') {
            break;
        }
        paths.push(arg);
    }
    return paths.map((path) => createAccess(path, 'read', command));
}

function extractGrepAccesses(args: readonly string[], command: readonly string[]): PathAccess[] {
    const pathArgs: string[] = [];
    let positionalIndex = 0;
    let skipNext = false;
    for (const arg of args) {
        if (skipNext) {
            skipNext = false;
            continue;
        }
        if (arg === '-e' || arg === '-f') {
            skipNext = true;
            continue;
        }
        if (arg.startsWith('-')) {
            continue;
        }
        if (positionalIndex === 0) {
            positionalIndex++;
            continue;
        }
        pathArgs.push(arg);
    }
    return pathArgs.map((path) => createAccess(path, 'read', command));
}

function extractRgAccesses(args: readonly string[], command: readonly string[]): PathAccess[] {
    const pathArgs: string[] = [];
    let positionalIndex = 0;
    let skipNext = false;
    for (const arg of args) {
        if (skipNext) {
            skipNext = false;
            continue;
        }
        if (
            arg === '-e' || arg === '-f' || arg === '-g' || arg === '-t' ||
            arg === '--glob' || arg === '--type'
        ) {
            skipNext = true;
            continue;
        }
        if (arg.startsWith('-')) {
            continue;
        }
        if (positionalIndex === 0) {
            positionalIndex++;
            continue;
        }
        pathArgs.push(arg);
    }
    return pathArgs.map((path) => createAccess(path, 'read', command));
}

function extractPowerShellValue(args: readonly string[], names: readonly string[]): string | undefined {
    const normalizedNames = new Set(names.map((name) => name.toLowerCase()));
    for (let i = 0; i < args.length - 1; i++) {
        if (normalizedNames.has((args[i] ?? '').toLowerCase())) {
            return args[i + 1];
        }
    }
    return undefined;
}

function extractPowerShellNonNamedArgs(args: readonly string[]): string[] {
    const values: string[] = [];
    let skipNext = false;
    for (const arg of args) {
        if (skipNext) {
            skipNext = false;
            continue;
        }
        if (arg.startsWith('-')) {
            skipNext = true;
            continue;
        }
        values.push(arg);
    }
    return values;
}

function extractPowerShellCopyLikeAccesses(
    args: readonly string[],
    command: readonly string[],
    sourceKind: PathAccessKind,
    targetKind: PathAccessKind,
): PathAccess[] {
    const source =
        extractPowerShellValue(args, ['-Path', '-LiteralPath']) ??
        extractPowerShellNonNamedArgs(args)[0];
    const target =
        extractPowerShellValue(args, ['-Destination']) ??
        extractPowerShellNonNamedArgs(args)[1];
    const accesses: PathAccess[] = [];
    if (source) {
        accesses.push(createAccess(source, sourceKind, command));
    }
    if (target) {
        accesses.push(createAccess(target, targetKind, command));
    }
    return accesses;
}

function extractSinglePathAccess(
    args: readonly string[],
    command: readonly string[],
    kind: PathAccessKind,
): PathAccess[] {
    const path =
        extractPowerShellValue(args, ['-Path', '-LiteralPath']) ??
        extractPowerShellNonNamedArgs(args)[0];
    return path ? [createAccess(path, kind, command)] : [];
}

/**
 * Extract the path accesses for a single (already-shell-decomposed) command.
 *
 * @internal
 */
function extractSingleCommandPathAccesses(command: readonly string[]): PathAccess[] {
    if (command.length === 0) {
        return [];
    }
    const args = command.slice(1);
    const commandName = normalizeCommandName(command[0] ?? '');
    switch (commandName) {
        case 'rm':
            return extractPositionalPathAccesses(args, 'delete', command);
        case 'mkdir':
            return extractPositionalPathAccesses(args, 'create', command);
        case 'rmdir':
            return extractPositionalPathAccesses(args, 'delete', command);
        case 'touch':
            return extractPositionalPathAccesses(args, 'create', command);
        case 'chmod':
        case 'chown':
            return extractPositionalPathAccesses(args, 'metadata', command);
        case 'cp':
            return extractCopyLikeAccesses(args, command, 'read', 'write');
        case 'mv':
            return extractCopyLikeAccesses(args, command, 'move_source', 'move_target');
        case 'cd':
            return extractPositionalPathAccesses(args, 'read', command);
        case 'ls':
        case 'cat':
        case 'head':
        case 'tail':
        case 'nl':
        case 'rev':
        case 'wc':
        case 'stat':
        case 'base64':
            return extractPositionalPathAccesses(args, 'read', command);
        case 'find':
            return extractFindAccesses(args, command);
        case 'grep':
            return extractGrepAccesses(args, command);
        case 'rg':
            return extractRgAccesses(args, command);
        case 'remove-item':
            return extractSinglePathAccess(args, command, 'delete');
        case 'move-item':
            return extractPowerShellCopyLikeAccesses(args, command, 'move_source', 'move_target');
        case 'copy-item':
            return extractPowerShellCopyLikeAccesses(args, command, 'read', 'write');
        case 'new-item':
            return extractSinglePathAccess(args, command, 'create');
        case 'set-content':
        case 'add-content':
            return extractSinglePathAccess(args, command, 'write');
        case 'get-content':
        case 'get-childitem':
        case 'test-path':
            return extractSinglePathAccess(args, command, 'read');
        case 'del':
        case 'erase':
            return extractPositionalPathAccesses(args, 'delete', command);
        case 'copy':
            return extractCopyLikeAccesses(args, command, 'read', 'write');
        case 'move':
            return extractCopyLikeAccesses(args, command, 'move_source', 'move_target');
        case 'md':
            return extractPositionalPathAccesses(args, 'create', command);
        case 'dir':
        case 'type':
            return extractPositionalPathAccesses(args, 'read', command);
        default:
            return [];
    }
}

/**
 * Extract path accesses from a (possibly-shell-wrapped) argv.
 *
 * @public
 */
export function extractCommandPathAccesses(argv: readonly string[]): PathAccess[] {
    return parseCommand(argv).flatMap((command) => [
        ...extractSingleCommandPathAccesses(command),
        ...extractRedirectedPathAccesses(command),
    ]);
}

/**
 * Top-level command analysis: decompose into sub-commands, classify each,
 * and gather all path accesses.
 *
 * @public
 */
export function analyzeCommand(argv: readonly string[]): {
    subCommands: readonly (readonly string[])[];
    classifications: readonly CommandClassification[];
    pathAccesses: readonly PathAccess[];
} {
    const subCommands = parseCommand(argv);
    return {
        subCommands,
        classifications: subCommands.map((command) => classifyCommandForAnalyzer(command)),
        pathAccesses: extractCommandPathAccesses(argv),
    };
}
