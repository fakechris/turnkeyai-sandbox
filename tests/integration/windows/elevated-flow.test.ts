/**
 * Integration tests for the Windows elevated/restricted-token flow.
 *
 * On macOS these tests verify that every FFI-dependent function throws
 * a clear error (or SandboxUnsupportedError) when called outside win32.
 * This catches regressions where a refactor might accidentally bypass
 * the platform guard.
 *
 * On Windows (CI) these tests are skipped — the unit tests cover the
 * happy-path logic; a full e2e would need a provisioned sandbox user.
 */
import { describe, expect, it } from 'vitest';

import { createAclEditSession } from '../../../src/sandbox/windows-sandbox/legacy/acl-editor.js';
import { createJobObject, assignProcessToJob } from '../../../src/sandbox/windows-sandbox/legacy/job-object.js';
import {
    createRestrictedToken,
    createProcessAsRestrictedToken,
} from '../../../src/sandbox/windows-sandbox/legacy/restricted-token.js';
import {
    logonSandboxUser,
    createProcessWithLogon,
} from '../../../src/sandbox/windows-sandbox/elevated/logon-user.js';
import { setupSandboxFirewall } from '../../../src/sandbox/windows-sandbox/elevated/firewall-netsh.js';

const isWin32 = process.platform === 'win32';

describe('Windows FFI functions on non-Windows', { skip: isWin32 }, () => {
    // ── ACL Editor ─────────────────────────────────────────────

    describe('createAclEditSession', () => {
        it('throws on non-Windows (FFI not available)', async () => {
            await expect(createAclEditSession()).rejects.toThrow();
        });
    });

    // ── Job Object ─────────────────────────────────────────────

    describe('createJobObject', () => {
        it('throws on non-Windows', async () => {
            await expect(createJobObject()).rejects.toThrow();
        });
    });

    describe('assignProcessToJob', () => {
        it('throws on non-Windows', async () => {
            await expect(assignProcessToJob(0x1, 0x2)).rejects.toThrow();
        });
    });

    // ── Restricted Token ───────────────────────────────────────

    describe('createRestrictedToken', () => {
        it('throws on non-Windows (FFI error — getWindowsFFI throws)', async () => {
            await expect(createRestrictedToken()).rejects.toThrow();
        });

        it('throws on non-Windows even with a SID argument', async () => {
            await expect(createRestrictedToken('S-1-5-21-123-456-789-0')).rejects.toThrow();
        });
    });

    describe('createProcessAsRestrictedToken', () => {
        it('throws SandboxUnsupportedError on non-Windows', async () => {
            await expect(
                createProcessAsRestrictedToken(0x1, 'echo hello', 'C:\\', {}),
            ).rejects.toThrow(/only available on Windows/);
        });
    });

    // ── Elevated: Logon + CreateProcess ────────────────────────

    describe('logonSandboxUser', () => {
        it('throws SandboxUnsupportedError on non-Windows', async () => {
            await expect(
                logonSandboxUser('sandboxuser', 'password123'),
            ).rejects.toThrow(/only available on Windows/i);
        });
    });

    describe('createProcessWithLogon', () => {
        it('throws SandboxUnsupportedError on non-Windows', async () => {
            await expect(
                createProcessWithLogon('sandboxuser', 'password123', 'echo hello', 'C:\\', {}),
            ).rejects.toThrow(/only available on Windows/i);
        });
    });

    // ── Firewall (netsh subprocess) ────────────────────────────

    describe('setupSandboxFirewall', () => {
        it('throws on non-Windows (netsh not found)', async () => {
            // netsh doesn't exist on macOS/Linux — the child_process
            // spawn will fail with ENOENT or a non-zero exit code.
            await expect(
                setupSandboxFirewall('S-1-5-21-123-456-789-0'),
            ).rejects.toThrow();
        });
    });
});
