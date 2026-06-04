# @turnkeyai/sandbox

Cross-platform OS-level command sandbox with a policy engine, a
host-proxy, and a banned-prefix anti-bypass table.

- **macOS** — generates Seatbelt (SBPL) profiles and runs the user's command
  under `sandbox-exec`
- **Linux** — wraps the user's command under `bwrap` (bubblewrap)
- **Windows** — uses koffi to call Win32 directly (JobObject + Restricted
  Token, with an optional LogonUserW + CreateProcessWithLogonW elevated mode)
- **Banned-prefix table** — 40 anti-bypass patterns hard-coded
  (`bash -c`, `node -e`, `sudo`, `pwsh -Command`, …) that the engine
  physically refuses to allow
- **Shell command policy engine** — heuristic classification (safe /
  dangerous / unknown), approval policies (`never` / `on-request` /
  `unless-trusted`), session approval memo, amendment proposals
- **Host proxy** — SOCKS5 no-auth + HTTP CONNECT on 127.0.0.1, with
  `*.example.com` subdomain support, a dangerous TLD denylist, and an
  async `ask` callback for unknown hosts

## Install

```bash
npm install @turnkeyai/sandbox
```

The only native dependency is `koffi`, used exclusively on Windows
hosts. On macOS / Linux, koffi is installed but never loaded.

## Quick start

### Library

```ts
import { runInSandbox, compileConfig, buildSbplProfile } from '@turnkeyai/sandbox';

// 1. Define a policy
const policy = compileConfig({
    filesystem: {
        mode: 'workspaceWrite',
        writableRoots: [
            { path: '/Users/me/work', readOnlySubpaths: ['.git', 'node_modules'] },
        ],
        readableRoots: [],
    },
    network: {
        mode: 'restricted',
        allowedHosts: ['github.com', '*.npmjs.org'],
    },
});

// 2. Run a command inside the sandbox
const result = await runInSandbox(['npm', 'test'], {
    policy,
    cwd: '/Users/me/work',
    timeoutMs: 60_000,
});
console.log('exit', result.exitCode);
console.log(result.stdout);

// 3. Inspect the generated SBPL on macOS
if (process.platform === 'darwin') {
    console.log(buildSbplProfile(policy, { cwd: '/Users/me/work' }));
}
```

### CLI

```bash
# Detect host capabilities
$ npx turnkeyai-sandbox detect
platform: darwin
shell: /bin/zsh
sandbox-exec: /usr/bin/sandbox-exec

# Validate a policy
$ npx turnkeyai-sandbox policy-check --policy examples/policy.read-only.json
{
  "ok": true,
  "sandboxType": "macosSeatbelt",
  "platform": "darwin",
  ...
}

# Print the generated SBPL
$ npx turnkeyai-sandbox dump-sbpl --policy examples/policy.read-only.json
(version 1)
(deny default)
(allow process*)
...

# Run a command inside the sandbox
$ npx turnkeyai-sandbox run --policy examples/policy.workspace-write.json -- echo "hello"
hello
```

## Example policies

`examples/policy.read-only.json` — strictly read-only, with one
explicitly readable scratch dir.

`examples/policy.workspace-write.json` — writeable workspace, with
`.git` and `node_modules` locked down read-only.

## Architecture

```
src/
├── types/                 # Public result / platform / error types
├── util/                  # argv quoting, shell detection, safe JSON
├── policy/                # command policy engine
│   ├── command/           # tokenize, classify, path-access extract
│   ├── rules/             # 40 banned prefixes, rule schema, loader
│   └── engine/            # ExecPolicyManager state machine
└── sandbox/               # cross-platform sandbox backends
    ├── protocol/          # types + type guards
    ├── network/           # allowlist, host-proxy (HTTP + SOCKS5)
    ├── sandboxing/        # compile, sandbox-manager, run-in-sandbox
    ├── macos-sandbox/     # SBPL builder, log-stream-watcher
    ├── linux-sandbox/     # bubblewrap-args, socat-bridge
    └── windows-sandbox/   # koffi FFI, JobObject + ACL + Token
```

## Development

```bash
# Install deps
npm install

# Run unit tests
npm test

# Type-check
npm run lint      # tsc --noEmit

# Run the demo CLI
npm run demo      # tsx bin/turnkeyai-sandbox.ts ...

# Build a distributable
npm run build
```

## License & attribution

This project is **Apache-2.0**. See `LICENSE`.

This project **spawns** `bubblewrap` (LGPL-2.0) on Linux. We do not link
against it; we exec it as a separate process. Per the LGPL-2.0
Section 0 ("The act of running a program using the Library is not
restricted") and Section 2 (mere aggregation), this does not impose
any copyleft on this project. We also attribute `bubblewrap` in
`NOTICE`.

The macOS sandbox backend uses the system-provided `sandbox-exec`
(no license obligations). The Windows backend uses `koffi` (MIT) and
Win32 APIs (system).
