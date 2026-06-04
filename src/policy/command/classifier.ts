/**
 * Command safety classifier.
 *
 * Reverse-engineered from
 * `packages/sandbox-policy/src/command/classifier.ts` .
 *
 * Each command is classified into one of:
 *   - `safe`     — read-only / non-destructive, no surprise
 *   - `dangerous` — clearly destructive (e.g. `rm -rf`)
 *   - `unknown`  — neither side can prove its case
 *
 * Recursion through `sudo` is preserved: wrapping a dangerous command in
 * sudo makes it dangerous; wrapping anything else makes it `unknown`
 * (privilege escalation alone is treated as needing user review).
 *
 * @public
 */

import type { CommandClassification } from '../../types/result.js';
import { normalizeCommandName } from './common.js';

/** Commands that are safe regardless of arguments. */
const UNCONDITIONAL_SAFE = new Set([
    'cat',
    'cd',
    'cut',
    'echo',
    'expr',
    'false',
    'grep',
    'head',
    'id',
    'ls',
    'nl',
    'paste',
    'pwd',
    'rev',
    'seq',
    'stat',
    'tail',
    'tr',
    'true',
    'uname',
    'uniq',
    'wc',
    'which',
    'whoami',
]);

/** Read-only git subcommands. */
const GIT_SAFE_SUBCOMMANDS = new Set(['status', 'log', 'diff', 'show', 'branch']);

/** Git global options that load external code or change git's working state. */
const GIT_UNSAFE_GLOBAL_OPTIONS = new Set([
    '-c',
    '--config-env',
    '--exec-path',
    '--git-dir',
    '--namespace',
    '--super-prefix',
    '--work-tree',
]);

/** Per-subcommand git flags that can leak content or trigger code. */
const GIT_UNSAFE_SUBCOMMAND_FLAGS = new Set([
    '--output',
    '--ext-diff',
    '--textconv',
    '--exec',
    '--paginate',
]);

/** `find` flags that execute commands. */
const FIND_UNSAFE_FLAGS = new Set([
    '-exec',
    '-execdir',
    '-ok',
    '-okdir',
    '-delete',
    '-fls',
    '-fprint',
    '-fprint0',
    '-fprintf',
]);

function safe(reason: string): CommandClassification {
    return { safety: 'safe', reason };
}
function dangerous(reason: string): CommandClassification {
    return { safety: 'dangerous', reason };
}
function unknown(reason: string): CommandClassification {
    return { safety: 'unknown', reason };
}

function classifyBase64(argv: readonly string[]): CommandClassification {
    const args = argv.slice(1);
    for (const arg of args) {
        if (arg === '-o' || arg === '--output') {
            return unknown('base64 with output flag');
        }
    }
    return safe('base64 without output redirection');
}

function classifyFind(argv: readonly string[]): CommandClassification {
    const args = argv.slice(1);
    for (const arg of args) {
        if (FIND_UNSAFE_FLAGS.has(arg)) {
            return unknown(`find with unsafe flag: ${arg}`);
        }
    }
    return safe('find without unsafe flags');
}

function classifyRg(argv: readonly string[]): CommandClassification {
    const args = argv.slice(1);
    for (const arg of args) {
        if (arg === '--pre' || arg.startsWith('--pre=')) {
            return unknown('rg with --pre flag');
        }
        if (arg === '--hostname-bin' || arg.startsWith('--hostname-bin=')) {
            return unknown('rg with --hostname-bin flag');
        }
        if (arg === '--search-zip' || arg === '-z') {
            return unknown('rg with --search-zip flag');
        }
    }
    return safe('rg without unsafe flags');
}

function classifyGit(argv: readonly string[]): CommandClassification {
    const args = argv.slice(1);
    // Parse global options vs subcommand
    let subcommandIndex = -1;
    for (let i = 0; i < args.length; i++) {
        const arg = args[i] ?? '';
        // Check for unsafe global options
        if (GIT_UNSAFE_GLOBAL_OPTIONS.has(arg)) {
            return unknown(`git with unsafe global option: ${arg}`);
        }
        // First non-flag argument is the subcommand
        if (!arg.startsWith('-')) {
            subcommandIndex = i;
            break;
        }
    }
    if (subcommandIndex === -1) {
        return unknown('git without subcommand');
    }
    const subcommand = args[subcommandIndex] ?? '';
    if (!GIT_SAFE_SUBCOMMANDS.has(subcommand)) {
        return unknown(`git subcommand not in safe list: ${subcommand}`);
    }
    // Check subcommand flags
    const subArgs = args.slice(subcommandIndex + 1);
    for (const arg of subArgs) {
        if (GIT_UNSAFE_SUBCOMMAND_FLAGS.has(arg)) {
            return unknown(`git ${subcommand} with unsafe flag: ${arg}`);
        }
    }
    return safe(`git ${subcommand} is a read-only subcommand`);
}

function classifySed(argv: readonly string[]): CommandClassification {
    // Safe only for: sed -n <pattern>p (exactly 3 args total: sed, -n, <pattern>)
    const args = argv.slice(1);
    if (args.length !== 2) {
        return unknown('sed with unexpected argument count');
    }
    if (args[0] !== '-n') {
        return unknown('sed without -n flag');
    }
    const pattern = args[1] ?? '';
    // Match patterns like "5p" or "3,10p"
    if (/^\d+(,\d+)?p$/.test(pattern)) {
        return safe('sed -n with numeric print pattern');
    }
    return unknown('sed with non-numeric pattern');
}

function classifyRm(argv: readonly string[]): CommandClassification {
    if (argv.length < 2) {
        return unknown('rm without arguments');
    }
    // Check all args for force/recursive flags
    let hasForce = false;
    for (let i = 1; i < argv.length; i++) {
        const arg = argv[i] ?? '';
        if (arg === '--') {
            break; // stop at --
        }
        if (arg === '-f' || arg === '-rf' || arg === '-fr' || arg === '--force') {
            hasForce = true;
            break;
        }
        // Check combined short flags like -rfi, -fv, etc.
        if (arg.startsWith('-') && !arg.startsWith('--') && arg.includes('f')) {
            hasForce = true;
            break;
        }
    }
    if (hasForce) {
        return dangerous('rm with force flag');
    }
    return unknown('rm without force flag');
}

/**
 * Classify a command argv for safety.
 *
 * @public
 */
export function classifyCommand(argv: readonly string[]): CommandClassification {
    if (argv.length === 0) {
        return unknown('empty command');
    }
    const commandBasename = normalizeCommandName(argv[0] ?? '');
    // Handle sudo: strip and re-classify
    if (commandBasename === 'sudo') {
        const inner = argv.slice(1);
        if (inner.length === 0) {
            return unknown('sudo without command');
        }
        const innerResult = classifyCommand(inner);
        if (innerResult.safety === 'dangerous') {
            return dangerous(`sudo: ${innerResult.reason}`);
        }
        // sudo wrapping makes anything not-dangerous become unknown
        return unknown(`sudo: ${innerResult.reason}`);
    }
    // Unconditional safe
    if (UNCONDITIONAL_SAFE.has(commandBasename)) {
        return safe(`${commandBasename} is unconditionally safe`);
    }
    // Conditional safe
    if (commandBasename === 'base64') {
        return classifyBase64(argv);
    }
    if (commandBasename === 'find') {
        return classifyFind(argv);
    }
    if (commandBasename === 'rg') {
        return classifyRg(argv);
    }
    if (commandBasename === 'git') {
        return classifyGit(argv);
    }
    if (commandBasename === 'sed') {
        return classifySed(argv);
    }
    // Dangerous
    if (commandBasename === 'rm') {
        return classifyRm(argv);
    }
    return unknown(`unknown command: ${commandBasename}`);
}

/** Returns true if the command is classified as safe. @public */
export function isSafeCommand(argv: readonly string[]): boolean {
    return classifyCommand(argv).safety === 'safe';
}

/** Returns true if the command is classified as dangerous. @public */
export function isDangerousCommand(argv: readonly string[]): boolean {
    return classifyCommand(argv).safety === 'dangerous';
}
