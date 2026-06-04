#!/usr/bin/env node
/**
 * turnkeyai-sandbox — demo CLI for the @turnkeyai/sandbox/local package.
 *
 * Subcommands:
 *   -v / --version     print version
 *   -h / --help        print help
 *   detect             detect platform, shell, bwrap, sandbox
 *   run                run a command inside a sandbox policy
 *   dump-sbpl          print the SBPL profile a macOS sandbox would get
 *   dump-bwrap         print the bwrap argv a Linux sandbox would get
 *   policy-check       validate a policy JSON without running anything
 *
 * @public
 */
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { VERSION } from '../src/version.js';
import { getPlatform } from '../src/util/platform.js';
import { compileConfig } from '../src/sandbox/sandboxing/compile.js';
import { runInSandbox } from '../src/sandbox/sandboxing/run-in-sandbox.js';
import { SandboxManager } from '../src/sandbox/sandboxing/sandbox-manager.js';
import { buildSbplProfile } from '../src/sandbox/macos-sandbox/sbpl-builder.js';
import { buildBubblewrapArgs } from '../src/sandbox/linux-sandbox/bubblewrap-args.js';
import { argvQuoteJoinPosix as _argvQuoteJoinPosix } from '../src/util/argv-quote.js';
void _argvQuoteJoinPosix;

const argv = process.argv.slice(2);
const cmd = argv[0];

function printHelp(): void {
    process.stdout.write(`turnkeyai-sandbox ${VERSION} (${getPlatform()})

Usage: turnkeyai-sandbox <command> [args]

Commands:
  -v, --version              print version
  -h, --help                 print this help
  detect                     detect platform, shell, bwrap, sandbox
  run --policy FILE -- CMD   run CMD inside the sandbox policy from FILE
  dump-sbpl --policy FILE    print the SBPL a macOS sandbox would emit
  dump-bwrap --policy FILE   print the bwrap argv a Linux sandbox would emit
  policy-check --policy FILE  validate a policy JSON without running

Examples:
  turnkeyai-sandbox run --policy examples/policy.read-only.json -- ls -la
  turnkeyai-sandbox dump-sbpl --policy examples/policy.read-only.json
  turnkeyai-sandbox policy-check --policy examples/policy.read-only.json
`);
}

function which(bin: string): string | null {
    const r = spawnSync('which', [bin], { encoding: 'utf8' });
    return r.status === 0 ? r.stdout.trim() : null;
}

function cmdDetect(): void {
    const p = getPlatform();
    process.stdout.write(`platform: ${p}\n`);
    process.stdout.write(`shell: ${process.env.SHELL ?? 'unknown'}\n`);
    if (p === 'darwin') {
        const sb = which('sandbox-exec');
        process.stdout.write(`sandbox-exec: ${sb ?? 'NOT FOUND'}\n`);
    } else if (p === 'linux') {
        const bw = which('bwrap');
        process.stdout.write(`bwrap: ${bw ?? 'NOT FOUND'}\n`);
        const so = which('socat');
        process.stdout.write(`socat: ${so ?? 'NOT FOUND'}\n`);
    }
}

interface ParsedFlags {
    policyFile?: string;
    cmdArgs: string[];
    timeout?: number;
    cwd?: string;
}

function parseFlags(restArgs: string[]): ParsedFlags {
    const out: ParsedFlags = { cmdArgs: [] };
    let i = 0;
    while (i < restArgs.length) {
        const a = restArgs[i];
        if (a === '--policy' && i + 1 < restArgs.length) {
            out.policyFile = restArgs[i + 1];
            i += 2;
        } else if (a === '--timeout' && i + 1 < restArgs.length) {
            out.timeout = Number(restArgs[i + 1]);
            i += 2;
        } else if (a === '--cwd' && i + 1 < restArgs.length) {
            out.cwd = restArgs[i + 1];
            i += 2;
        } else if (a === '--') {
            out.cmdArgs = restArgs.slice(i + 1);
            break;
        } else {
            out.cmdArgs.push(a);
            i++;
        }
    }
    return out;
}

function loadPolicy(file: string): ReturnType<typeof compileConfig> {
    const raw = JSON.parse(readFileSync(file, 'utf-8'));
    return compileConfig(raw);
}

async function cmdRun(flags: ParsedFlags): Promise<number> {
    if (!flags.policyFile) {
        process.stderr.write('run: --policy <file> is required\n');
        return 2;
    }
    const policy = loadPolicy(flags.policyFile);
    const result = await runInSandbox(flags.cmdArgs, {
        policy,
        cwd: flags.cwd,
        timeoutMs: flags.timeout,
    });
    process.stdout.write(result.stdout);
    process.stderr.write(result.stderr);
    if (process.env.TURNKEYAI_SANDBOX_VERBOSE === '1') {
        process.stderr.write(
            `\n[turnkeyai-sandbox] sandbox=${result.sandboxType} exit=${result.exitCode} ` +
                `timedOut=${result.timedOut} durationMs=${result.durationMs}\n` +
                `[turnkeyai-sandbox] wrapped: ${result.wrappedCommand.slice(0, 200)}${result.wrappedCommand.length > 200 ? '…' : ''}\n`,
        );
    }
    return result.exitCode;
}

function cmdDumpSbpl(flags: ParsedFlags): number {
    if (!flags.policyFile) {
        process.stderr.write('dump-sbpl: --policy <file> is required\n');
        return 2;
    }
    const policy = loadPolicy(flags.policyFile);
    const sbpl = buildSbplProfile(policy, { cwd: flags.cwd });
    process.stdout.write(sbpl + '\n');
    return 0;
}

function cmdDumpBwrap(flags: ParsedFlags): number {
    if (!flags.policyFile) {
        process.stderr.write('dump-bwrap: --policy <file> is required\n');
        return 2;
    }
    const policy = loadPolicy(flags.policyFile);
    const argv = buildBubblewrapArgs(
        { argv: flags.cmdArgs.length > 0 ? flags.cmdArgs : ['/bin/sh'], cwd: flags.cwd },
        policy,
        { cwd: flags.cwd },
    );
    process.stdout.write('bwrap ' + argv.map((a) => (a.includes(' ') ? `'${a}'` : a)).join(' ') + '\n');
    return 0;
}

function cmdPolicyCheck(flags: ParsedFlags): number {
    if (!flags.policyFile) {
        process.stderr.write('policy-check: --policy <file> is required\n');
        return 2;
    }
    try {
        const policy = loadPolicy(flags.policyFile);
        const mgr = new SandboxManager(policy);
        const t = mgr.selectInitial();
        process.stdout.write(
            JSON.stringify(
                {
                    ok: true,
                    sandboxType: t,
                    platform: mgr.platform,
                    policy: {
                        fsMode: policy.filesystem.mode,
                        writableRoots: policy.filesystem.writableRoots.length,
                        readableRoots: policy.filesystem.readableRoots.length,
                        networkMode: policy.network.mode,
                        allowedHosts: policy.network.allowedHosts?.length ?? 0,
                    },
                },
                null,
                2,
            ) + '\n',
        );
        return 0;
    } catch (err) {
        const e = err as Error;
        process.stderr.write(`policy-check failed: ${e.message}\n`);
        return 1;
    }
}

async function main(): Promise<number> {
    if (cmd === '-v' || cmd === '--version' || cmd === undefined) {
        process.stdout.write(`turnkeyai-sandbox ${VERSION} (${getPlatform()})\n`);
        return 0;
    }
    if (cmd === '-h' || cmd === '--help') {
        printHelp();
        return 0;
    }
    const rest = argv.slice(1);
    const flags = parseFlags(rest);
    switch (cmd) {
        case 'detect':
            cmdDetect();
            return 0;
        case 'run':
            return cmdRun(flags);
        case 'dump-sbpl':
            return cmdDumpSbpl(flags);
        case 'dump-bwrap':
            return cmdDumpBwrap(flags);
        case 'policy-check':
            return cmdPolicyCheck(flags);
        default:
            process.stderr.write(`turnkeyai-sandbox: unknown command "${cmd}" (try --help)\n`);
            return 2;
    }
}

main().then(
    (code) => process.exit(code),
    (err) => {
        process.stderr.write(`turnkeyai-sandbox: fatal: ${(err as Error).message}\n`);
        process.exit(1);
    },
);
