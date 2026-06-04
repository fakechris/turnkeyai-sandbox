# Windows Sandbox — Coze Bundle Diff

> Compares `src/sandbox/windows-sandbox/` in this repo (turnkeyai-sandbox)
> against the corresponding modules in Coze Desktop's `app/main/main.js`
> bundle (extracted from `/Users/chris/coze-reverse/extracted/app/main/main.js`).
>
> The Coze source paths are `packages/sandbox-exec/src/windows-sandbox/*`
> per the `// CONCATENATED MODULE` headers in the bundle.

## Summary

| Module | Files | Status | Risk |
|---|---|---|---|
| `ffi/koffi-bindings.ts` | 1 | **Behavioral divergence** (rename + 24 extras) | High — naming/quantity mismatch makes upstream syncs harder |
| `ffi/windows-ffi-factory.ts` | 1 | **Behavioral divergence** (sync vs async; no koffi.struct) | Medium — FFI works on win32, but Coze's lazy `await` semantics lost |
| `legacy/job-object.ts` | 1 | **Logic identical**, constant renamed | Low |
| `legacy/acl-editor.ts` | 1 | **Logic identical** | Low |
| `legacy/restricted-token.ts` | 1 | **Logic identical** (1 minor cleanup) | Low |
| `elevated/logon-user.ts` | 1 | **Logic identical** | Low |
| `elevated/firewall-netsh.ts` | 1 | **Logic identical**, rule prefix rebranded | Low |
| `apply-filesystem-acl-policy.ts` | 1 | **STUB** — does not apply ACLs | **High** — silently no-op |
| `setup-version.ts` | 1 | **Logic identical** (function shapes match) | Low |
| `sid-utils.ts` | 1 | **Behavioral divergence** (different SID algorithm) | High — different SIDs = stale setup state |
| `index.ts` (WindowsBackend) | 1 | **STUB** — does not orchestrate FFI | **High** — silent passthrough |

---

## Module-by-module

### 1. `ffi/koffi-bindings.ts`

**Coze (bundle line 39847–39920, ~30 lines)** exports **26 constants**.
**Our port** exports **~50 constants** — a strict superset.

**Behavioral differences:**

| Constant | Coze | Our port | Notes |
|---|---|---|---|
| `JOB_OBJECT_EXTENDED_LIMIT_INFORMATION` | `= 9` (UPPER_CASE) | `JobObjectExtendedLimitInformation` (PascalCase) | **RENAMED.** The previous session's "constant naming fix" diverged from Coze. Every call site now references the new name; reverting would require re-editing `legacy/job-object.ts`. |
| `LOGON32_LOGON_BATCH` | `koffi_bindings_LOGON32_LOGON_BATCH = 4` (webpack-rename prefix) | `LOGON32_LOGON_BATCH = 4` | Bundle uses webpack's `/* inlined export .X */` markers; we drop the prefix. |
| `LOGON32_PROVIDER_DEFAULT` | `koffi_bindings_LOGON32_PROVIDER_DEFAULT = 0` | `LOGON32_PROVIDER_DEFAULT = 0` | Same as above. |

**Extras in our port (24 constants not in Coze):**
- Logon: `LOGON32_LOGON_INTERACTIVE/NETWORK/SERVICE`, `LOGON32_PROVIDER_WINNT50`, `LOGON_NETCREDENTIALS_ONLY`
- Token restriction: `SANDBOX_INERT`, `LUA_TOKEN`, `WRITE_RESTRICTED`
- Job: `JOB_OBJECT_LIMIT_BREAKAWAY_OK/SILENT_BREAKAWAY_OK`, `JobObjectBasicProcessIdList`
- Process: `CREATE_BREAKAWAY_FROM_JOB`, `EXTENDED_STARTUPINFO_PRESENT`
- SE_OBJECT_TYPE: `SE_KERNEL_OBJECT`, `SE_REGISTRY_KEY`, `SE_SERVICE`
- SECURITY_INFORMATION: `OWNER/GROUP/SACL/PROTECTED_DACL/UNPROTECTED_DACL_SECURITY_INFORMATION`
- ACE: `REVOKE_ACCESS`, `SUB_OBJECTS_ONLY_INHERIT`, `INHERIT_NO_PROPAGATE`
- File rights: `FILE_GENERIC_EXECUTE`, `FILE_READ/WRITE/APPEND_DATA`, `FILE_READ/WRITE_EA`, `FILE_EXECUTE`
- Process rights: `PROCESS_ALL_ACCESS` + 12 `PROCESS_*` constants
- Wait: `STILL_ACTIVE`, `STARTF_USESTDHANDLES`
- Setup: `ERROR_ALREADY_EXISTS`

None of these are referenced by our current port — they're dead exports waiting for a future use case. Carrying them bloats the constant table; Coze only exports what its code actually uses.

**Verdict:** The rename is the substantive issue. The extras are noise but harmless.

---

### 2. `ffi/windows-ffi-factory.ts`

**Coze (bundle line 39615–39846)** structure:
- `createWindowsBindingTypes(koffi)` — defines **5 koffi.struct** types:
  - `sidAndAttributes` (Sid: pSid, Attributes: uint32)
  - `trusteeW` (pMultipleTrustee, MultipleTrusteeOperation, TrusteeForm, TrusteeType, ptstrName: pSid)
  - `explicitAccessW` (grfAccessPermissions, grfAccessMode, grfInheritance, Trustee: trusteeW)
  - Plus pointer types for all of them
- `bindKernel32Functions` / `bindAdvapi32Functions` — declare `koffi.func(...)` for each Win32 API
- `createSecurityFFI` / `createProcessHelperFFI` / `createElevatedFFI` / `createJobObjectFFI` — wrap raw koffi funcs in named closures
- `createWindowsFFIFromKoffi(koffi)` — composer (synchronous)
- `koffi_bindings_getWindowsFFI` — **async**, uses `await Promise.resolve(...)` + dynamic `__webpack_require__.t(1041, 23)` to lazy-import koffi
- `resetFFICache()` — clears `ffiCache = null`

**Our port** structure:
- `WindowsFFI` interface — TS-level signature for the 20+ methods
- `KoffiHandle` — partial interface
- `getWindowsFFI()` — **synchronous**, uses `import * as koffiModule from 'koffi'` (static)
- No koffi.struct definitions — callers pass plain JS objects for `Trustee`/`explicitAccessW`
- `resetWindowsFFICache()` — clears `cached = undefined`

**Differences:**

| Aspect | Coze | Our port | Impact |
|---|---|---|---|
| Sync vs async | `getWindowsFFI` is async (lazy-imports koffi via `await Promise.resolve(...)`) | `getWindowsFFI` is sync (static import) | Our non-win32 host throws synchronously, Coze's throws via rejected Promise. Call sites must `await`. |
| koffi struct | Uses `koffi.struct` for `sidAndAttributes`, `trusteeW`, `explicitAccessW` | Uses raw `koffi.pointer(handle)`; relies on koffi to accept JS objects | Works because koffi is permissive, but loses the type-checking benefit Coze gets from structs. |
| Sub-export split | 4 wrappers (`createSecurityFFI`, `createProcessHelperFFI`, `createElevatedFFI`, `createJobObjectFFI`) composed via spread | Single flat `WindowsFFI` interface | Cosmetic. Coze's split is a webpack-tree-shaking hint. |
| `null` parameter types | `lpwstr` (`'str16'`) — koffi allows NULL pointer | TS signature declared `string` (now widened to `string | null` for 4 params after my fix) | My commit `e20736f` aligned us with Coze — both now accept `null`. |

**Verdict:** Functionally equivalent on Windows. The async/sync divergence is the most significant — it's deliberate (Coze lazy-imports; we static-import) but means call sites must `await getWindowsFFI()`.

---

### 3. `legacy/job-object.ts`

**Identical logic** modulo the constant rename.

Coze (bundle line 39990–40046):
```js
ffi.setInformationJobObject(jobHandle, (/* JOB_OBJECT_EXTENDED_LIMIT_INFORMATION */9), ...);
```

Our port:
```ts
ffi.setInformationJobObject(jobHandle, JobObjectExtendedLimitInformation, ...);
```

**`getExtendedLimitInformationSize()`** is identical: 144 bytes for x64/arm64, 112 for x86.

**`createJobObject()`** and **`assignProcessToJob()`** bodies are byte-for-byte equivalent.

**Verdict:** ✓ Logic matches. The constant rename is the only divergence.

---

### 4. `legacy/acl-editor.ts`

**Identical logic.** Two cosmetic differences:

1. **Return type** — Coze's `createAclEditSession` is non-`async` and returns `Promise.resolve(buildAclEditSession(...))` (a `Promise` that resolves synchronously to the session object). Our port is `async` and returns the session directly. Both yield `Promise<AclEditSession>` to the caller.

2. **Inner `addAce` re-fetches FFI** — both Coze and our port call `await getWindowsFFI()` inside `addAce` (Coze via `koffi_bindings_getWindowsFFI`, ours via `getWindowsFFI`). Same.

**`saveOriginalDacl`** — identical. `Map` keyed by path, holds `{ dacl, securityDescriptor }`.

**`revert`** — identical. Loops `originalDacls`, calls `setNamedSecurityInfoW`, then `localFree(securityDescriptor)`.

**Verdict:** ✓ Logic matches.

---

### 5. `legacy/restricted-token.ts`

**Logic identical** with one minor cleanup in `createProcessAsRestrictedToken`:

Coze (bundle line 40160–40164):
```js
const createProcessError = ok ? 0 : ffi.getLastError();
if (!ok) {
    throw new Error(`createProcessAsUserW failed with error ${createProcessError}`);
}
```
Coze computes `createProcessError` even on the success path (then discards it).

Our port (line 198–201):
```ts
if (!ok) {
    const err = ffi.getLastError();
    throw new Error(`createProcessAsUserW failed with error ${err}`);
}
```
Cleaner — only calls `getLastError` on failure.

**`createRestrictedToken`** — identical. Opens current process token, optionally converts string SID, calls `CreateRestrictedToken` with `DISABLE_MAX_PRIVILEGE`, attaches restricting SID.

**`buildWindowsEnvironmentBlock` / `createHiddenStartupInfo`** — identical (only diff: Coze's `restricted-token.ts` is one file with the helpers; `logon-user.ts` is a separate file with the same helpers re-defined as `logon_user_*` to avoid webpack module-scope collisions).

**Verdict:** ✓ Logic matches. Our cleanup is better.

---

### 6. `elevated/logon-user.ts`

**Logic identical.**

Coze (bundle line 40217–40297) and our port both:
1. `logonSandboxUser(accountName, password)`: calls `LogonUserW` with `LOGON32_LOGON_BATCH + LOGON32_PROVIDER_DEFAULT`, returns `{ token, cleanup }`
2. `createProcessWithLogon(accountName, password, commandLine, cwd, env)`: calls `CreateProcessWithLogonW` with `LOGON_WITH_PROFILE + CREATE_SUSPENDED + CREATE_UNICODE_ENVIRONMENT + CREATE_NO_WINDOW`

**Minor naming nit:** Coze's `logon-user.ts` uses `logon_user_*` for the helper function names (because the helpers collide with `restricted-token.ts`'s versions in the webpack bundle). Our port uses the unprefixed names because TS files are separately scoped.

**`null` argument for `applicationName`** — both Coze and our port pass `null` to `CreateProcessWithLogonW` for `applicationName` (line 142 in our port, ~line 40271 in Coze). Win32 allows NULL. **My fix to widen the FFI signature (`e20736f`) aligned us with Coze's actual call pattern.**

**Verdict:** ✓ Logic matches.

---

### 7. `elevated/firewall-netsh.ts`

**Logic identical.** Only difference: rule-name prefix.

| | Coze | Our port |
|---|---|---|
| Block rule name | `coze-sandbox-block-out-${sid}` | `turnkeyai-sandbox-block-out-${sid}` |
| Allow rule name | `coze-sandbox-allow-proxy-${sid}` | `turnkeyai-sandbox-allow-proxy-${sid}` |

**`addFirewallRule` / `removeFirewallRule`** — identical. Both build the same `netsh advfirewall firewall add/delete rule` argv (with `protocol=any` for block, `protocol=tcp` + `remoteport=...` for proxy-allow).

**`setupSandboxFirewall` cleanup** — identical. Best-effort try/catch in the loop, voiding the caught error.

**Verdict:** ✓ Logic matches. Rebrand is intentional.

---

### 8. `apply-filesystem-acl-policy.ts` ⚠️ STUB

This is the most important finding.

**Coze (bundle line 40406–40431):**
```js
async function applyWindowsFilesystemAclPolicy(session, policy, options) {
    const { sid } = options;
    async function addAclIfPathExists(targetPath, apply, action) {
        if (!existsSync(targetPath)) return;
        await apply(targetPath, sid);
    }
    for (const writableRoot of policy.filesystem.writableRoots) {
        await addAclIfPathExists(writableRoot.path, session.addAllowWriteAce, 'allow-write-root');
        for (const subpath of writableRoot.readOnlySubpaths) {
            const readOnlyPath = join(writableRoot.path, subpath);
            await addAclIfPathExists(readOnlyPath, session.addDenyWriteAce, 'deny-write-subpath');
        }
    }
    for (const readableRoot of policy.filesystem.readableRoots) {
        const alreadyWritable = policy.filesystem.writableRoots.some(...);
        if (!alreadyWritable) {
            await addAclIfPathExists(readableRoot, session.addAllowReadAce, 'allow-read-root');
        }
    }
}
```
Coze's version is a **thin orchestrator** that calls the `AclEditSession`'s `addAllowWriteAce` / `addDenyWriteAce` / `addAllowReadAce` methods. The actual FFI work (setEntriesInAclW + setNamedSecurityInfoW) lives in `acl-editor.ts`.

**Our port (89 lines):**
```ts
export async function applyWindowsFilesystemAclPolicy(
    writableRoots: readonly WritableRoot[],
    options: ApplyAclOptions = {},
): Promise<void> {
    if (process.platform !== 'win32') { throw ... }
    const ffi = getWindowsFFI();
    const sid = options.sid ?? getSandboxSid(options.cwd);
    for (const root of writableRoots) {
        const path = pathResolve(root.path);
        ffi.setEntriesInAclW(1, [allowAce(sid, FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE_ACCESS)], null, null);
        // ... elided
    }
    // ... more elided
}
function allowAce(sid: string, access: number): unknown {
    return { sid, access, mode: GRANT_ACCESS };   // ← NOT a real EXPLICIT_ACCESS_W
}
```

**Differences:**

| Aspect | Coze | Our port |
|---|---|---|
| Signature | `(session, policy, options)` — takes a ready-to-use AclEditSession | `(writableRoots, options)` — bypasses the session abstraction |
| Reads from | `policy.filesystem.writableRoots/readableRoots/readOnlySubpaths` | `writableRoots: readonly WritableRoot[]` (loses readableRoots!) |
| ACE shape | Delegates to `session.addAllowWriteAce(path, sid)` which builds the correct `EXPLICIT_ACCESS_W` | Builds a fake `{ sid, access, mode }` object that does NOT match `EXPLICIT_ACCESS_W` |
| `setNamedSecurityInfoW` | Called inside `acl-editor.ts` `addAce` | **Never called** — only `setEntriesInAclW` is called, and with the wrong shape |
| Hardcoded-deny paths | Iterates `policy.filesystem.writableRoots` to detect overlap | Has a hardcoded list `['.git', '.ssh', '.codex', '.agents', '.gnupg', '.config/gcloud']` |
| Actually applies ACL | ✓ Yes | ✗ **No — silent no-op on the filesystem** |

The comment in our port (line 86) admits this: *"The above constants are exported for completeness; the real koffi struct assembly is non-trivial and is left for a Windows-CI-tested implementation."*

**Verdict:** ❌ **STUB.** This file does not actually apply the filesystem ACL policy. On Windows, calling it would call `setEntriesInAclW` with malformed input and never call `setNamedSecurityInfoW`, so no DACL is ever written. The fix is to delegate to `createAclEditSession()` from `legacy/acl-editor.ts` (matching Coze's pattern).

---

### 9. `setup-version.ts`

**Logic identical** in shape; minor stylistic diffs.

| Function | Coze | Our port | Match |
|---|---|---|---|
| `SETUP_VERSION` | `= 1` | `= 1` | ✓ |
| `getSetupStatePath` | `%LOCALAPPDATA%\coze-sandbox\setup-state.json` | `${LOCALAPPDATA}/turnkeyai-sandbox/setup-state.json` (reb rand) | ⚠ Rebrand |
| `readSetupState` | `safeJsonParse(raw) ?? null` | `safeJsonParse(raw) ?? null` | ✓ |
| `writeSetupState` | `mkdirSync({ recursive: true })` + `writeFileSync` | same | ✓ |
| `isSetupRequired` | `state === null || state.version < SETUP_VERSION` | same | ✓ |
| `isSetupVersionMatch` | `state !== null && state.version === SETUP_VERSION` | same | ✓ |

**Verdict:** ✓ Logic matches. Rebrand on the storage path is intentional but means existing Coze-installed users would have to re-run setup when migrating.

---

### 10. `sid-utils.ts` ⚠️ BEHAVIORAL DIVERGENCE

The SID derivation algorithm is **different** between Coze and our port — and the difference matters because SIDs are persisted in `setup-state.json` and used to key ACLs and firewall rules.

**Coze (bundle line 40663–40698):**
```js
const SANDBOX_FIXED_SID = 'S-1-5-21-0-0-0-1000';  // fallback when cwd is undefined

function generateCapabilitySid(cwd) {
    const hash = createHash('sha256').update(cwd).digest();
    const sub1 = hash.readUInt32BE(0);
    const sub2 = hash.readUInt32BE(4);
    const sub3 = hash.readUInt32BE(8);
    const sub4 = hash.readUInt32BE(12);
    return `S-1-5-21-${sub1}-${sub2}-${sub3}-${sub4}`;   // 4 sub-authorities
}

function getSandboxSid(cwd) {
    if (cwd !== undefined) return generateCapabilitySid(cwd);
    return SANDBOX_FIXED_SID;
}
```

**Our port (lines 17–41):**
```ts
function bytesToSidString(bytes: Buffer): string {
    const subAuthority =
        ((bytes[0] ?? 0) << 24) | ((bytes[1] ?? 0) << 16) | ((bytes[2] ?? 0) << 8) | (bytes[3] ?? 0);
    const sid = `S-1-5-21-${(subAuthority >>> 0).toString()}-1-${toHex(bytes[4] ?? 0)}${toHex(bytes[5] ?? 0)}`;
    return sid;   // 1 big sub-authority + '-1-' + 2 hex chars
}

export function getSandboxSid(cwd: string = process.cwd()): string {
    const canonical = pathResolve(cwd);
    const hash = createHash('sha256').update(canonical).digest();
    return bytesToSidString(hash);
}
```

**Differences:**

| Aspect | Coze | Our port |
|---|---|---|
| Hash input | `cwd` (raw string) | `pathResolve(cwd)` (canonicalized) |
| Hash → SID | 4 × 32-bit sub-authorities (`S-1-5-21-A-B-C-D`) | 1 × 32-bit sub-authority + fixed `-1-` + 2 hex bytes (`S-1-5-21-X-1-YY`) |
| Fallback SID | `S-1-5-21-0-0-0-1000` (exported) | **Not exported** — `getSandboxSid()` always takes a `cwd` |
| Number of sub-authorities after `S-1-5-21-` | 4 | 3 (`X-1-YY` = 3 segments) |
| Also has `convertStringSidToSid` / `freeSid` helpers | ✓ | ✗ missing |

**Verdict:** ❌ **Behavioral divergence.** The SIDs produced by our port are structurally different from Coze's. Any `setup-state.json` written by Coze would not be readable by us (different SID for the same cwd), and vice versa. The fix is to mirror Coze's algorithm exactly.

---

### 11. `index.ts` (WindowsBackend) ⚠️ STUB

**Coze (bundle line 40724–40856, ~130 lines):** a full class with:
- `policy` field, `aclSession` field, `sandboxType` field
- `constructor(policy)`
- `wrap(req)` — returns `argv.map(argvQuoteWindows).join(' ')` with setup-state check for `windowsElevated`
- `capabilities()` — returns `networkEnforced`, `readOnlySupported`, `mitmSupported`, `violationStreamAvailable`
- **`initialize(policy)`** — creates AclEditSession, calls `applyWindowsFilesystemAclPolicy(session, policy, { cwd, homeDir, sid })`
- **`reset()`** — runs `elevatedCleanups.reverse()` + `aclSession.revert()`
- `getSandboxType()` — returns `this.sandboxType`
- `getSetupState()` — returns `readSetupState()`

**Our port (88 lines):** a class with:
- `wrap(req)` — returns `argv.map(argvQuotePosix).join(' ')` (note: **POSIX**, not Windows — bug!) for any sandboxType. **Does not call FFI, does not run setup.**
- `capabilities()` — returns a flat object (different shape than Coze: `processIsolation`/`syscallFilter`/`resourceLimits`/etc. instead of Coze's `networkEnforced`/`readOnlySupported`/`mitmSupported`)
- `isSetupRequired()` / `isSetupVersionMatch()` — read setup state
- `getSandboxType()` — returns based on setup-state match
- **Missing:** `initialize()`, `reset()`, `getSetupState()`, `policy` field, `aclSession` field, `sandboxType` field, `elevatedCleanups` array

**Verdict:** ❌ **STUB.** `wrap()` returns a passthrough command — it does not actually invoke the FFI-based sandboxing. The `argvQuotePosix` import (line 18) is wrong for Windows (should be `argvQuoteWindows`). Calling `WindowsBackend.wrap()` on a Windows host with `sandboxType: 'windowsRestrictedToken'` would just return a shell-quoted string, not a sandboxed process.

---

## Cross-cutting issues

### A. `JOB_OBJECT_EXTENDED_LIMIT_INFORMATION` rename
The previous session's edit renamed this constant from Coze's UPPER_CASE to PascalCase. **This was the wrong call** — it diverges from upstream and breaks any code (theirs or ours) that imports the original name. **Recommendation:** revert to `JOB_OBJECT_EXTENDED_LIMIT_INFORMATION`.

### B. Two high-risk stubs
`apply-filesystem-acl-policy.ts` and `index.ts` are skeletons that compile and pass tests but **do not actually sandbox anything** on Windows. Both have comments admitting this. They need a follow-up implementation pass that delegates to `legacy/acl-editor.ts` (per Coze's pattern) and wires the `wrap()` → `runInSandbox()` flow.

### C. Sync vs async `getWindowsFFI`
Coze: async, lazy-imports koffi. Our port: sync, static-imports. The decision is fine, but the public API surface is `await getWindowsFFI()` everywhere — this works because we kept the type as `WindowsFFI` (a synchronous value), so `await` is a no-op. If we ever switch to a real `Promise<WindowsFFI>`, the call sites don't need to change. The `// getWindowsFFI is cached + sync; await is a no-op kept for signature compat.` comment is correct.

### D. SID algorithm drift
Different SIDs from Coze = setup-state incompatibility. Either:
- (a) fix our algorithm to match Coze (4 sub-authorities, no path canonicalization)
- (b) declare the port a fork and document the divergence in README

### E. Capability table shape mismatch
Coze's `WindowsBackend.capabilities()` returns 4 fields; ours returns 11. These come from different spec versions. The two should be reconciled — pick Coze's shape (the reference) or document why we extended it.

---

## Recommended follow-ups (priority order)

1. **Fix `apply-filesystem-acl-policy.ts`** — delegate to `createAclEditSession()` + `addAllowWriteAce`/`addDenyWriteAce`/`addAllowReadAce`. Make it actually apply DACLs. (HIGH — silent no-op)
2. **Fix `index.ts` WindowsBackend** — implement `initialize()`/`reset()`, switch to `argvQuoteWindows`, make `wrap()` route through FFI. (HIGH — silent passthrough)
3. **Revert `JOB_OBJECT_EXTENDED_LIMIT_INFORMATION` rename** — go back to UPPER_CASE. (LOW — cosmetic)
4. **Match Coze's `sid-utils.ts` algorithm** — 4 sub-authorities, no `pathResolve` canonicalization, add `SANDBOX_FIXED_SID` fallback. (MEDIUM — setup-state compat)
5. **Trim `koffi-bindings.ts` extras** — drop the 24 unused constants. (LOW — bloat)
6. **Reconcile `capabilities()` shape** with Coze. (LOW — interface)

---

*Generated by comparing `src/sandbox/windows-sandbox/` against Coze Desktop `app/main/main.js` lines 39615–40856.*
