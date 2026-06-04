import { describe, expect, it } from 'vitest';
import {
    detectShell,
    encodePowerShellCommand,
    toShellArgv,
} from '../../../src/util/shell.js';

describe('encodePowerShellCommand', () => {
    it('encodes a command to base64(utf16le)', () => {
        const out = encodePowerShellCommand('echo hi');
        const decoded = Buffer.from(out, 'base64').toString('utf16le');
        expect(decoded).toBe('echo hi');
    });

    it('round-trips an empty string', () => {
        const out = encodePowerShellCommand('');
        expect(out).toBe('');
    });
});

describe('detectShell', () => {
    it('returns a shell on every supported platform', () => {
        const p = process.platform;
        const s = detectShell();
        expect(s.path.length).toBeGreaterThan(0);
        expect(['bash', 'zsh', 'sh', 'powershell', 'cmd']).toContain(s.type);
        if (p === 'win32') {
            expect(['powershell', 'cmd']).toContain(s.type);
        } else {
            expect(['bash', 'zsh', 'sh']).toContain(s.type);
        }
    });

    it('honours the explicit platform argument', () => {
        const s = detectShell('darwin');
        expect(['bash', 'zsh', 'sh']).toContain(s.type);
        const w = detectShell('win32');
        expect(['powershell', 'cmd']).toContain(w.type);
    });
});

describe('toShellArgv', () => {
    it('throws on empty input', () => {
        expect(() => toShellArgv('')).toThrow();
    });

    it('produces a POSIX shell-wrapped argv on non-Windows', () => {
        if (process.platform === 'win32') {
            return;
        }
        const argv = toShellArgv('ls -la');
        expect(argv.length).toBe(3);
        expect(argv[0]).toMatch(/\/(ba)?sh$|zsh$|\/sh$/);
        expect(['-c', '-lc', '-ic', '-ilc']).toContain(argv[1]);
        expect(argv[2]).toBe('ls -la');
    });

    it('uses login flag when requested', () => {
        if (process.platform === 'win32') {
            return;
        }
        const argv = toShellArgv('ls', { loginShell: true });
        expect(['-lc', '-ilc']).toContain(argv[1]);
    });

    it('uses interactive flag when requested', () => {
        if (process.platform === 'win32') {
            return;
        }
        const argv = toShellArgv('ls', { interactiveShell: true });
        expect(['-ic', '-ilc']).toContain(argv[1]);
    });

    it('produces a PowerShell argv on Windows', () => {
        if (process.platform !== 'win32') {
            return;
        }
        const argv = toShellArgv('Get-Process');
        expect(argv[0]).toMatch(/powershell|pwsh|cmd/i);
        expect(argv[1]).toBe('-NoProfile');
        expect(argv[2]).toBe('-EncodedCommand');
        const decoded = Buffer.from(argv[3] ?? '', 'base64').toString('utf16le');
        expect(decoded).toBe('Get-Process');
    });
});
