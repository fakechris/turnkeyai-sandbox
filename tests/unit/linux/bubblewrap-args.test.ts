import { describe, expect, it } from 'vitest';
import { buildBubblewrapArgs } from '../../../src/sandbox/linux-sandbox/bubblewrap-args.js';
import type { SandboxPolicy } from '../../../src/sandbox/protocol/sandbox-policy.js';

function policy(
    fsOverrides: Partial<SandboxPolicy['filesystem']> = {},
    netOverrides: Partial<SandboxPolicy['network']> = {},
): SandboxPolicy {
    return {
        filesystem: {
            mode: 'readOnly',
            writableRoots: [],
            readableRoots: [],
            includePlatformDefaults: true,
            ...fsOverrides,
        },
        network: { mode: 'open', ...netOverrides },
    };
}

describe('buildBubblewrapArgs', () => {
    it('starts with --tmpfs / and ends with -- argv', () => {
        const args = buildBubblewrapArgs({ argv: ['ls', '-la'] }, policy(), {
            homeDir: '/home/user',
            cwd: '/work',
        });
        expect(args[0]).toBe('--tmpfs');
        expect(args[1]).toBe('/');
        // Last three elements should be '--' + argv
        const idx = args.indexOf('--');
        expect(idx).toBeGreaterThan(0);
        expect(args.slice(idx + 1)).toEqual(['ls', '-la']);
    });

    it('mounts --dev /dev and --proc /proc', () => {
        const args = buildBubblewrapArgs({ argv: ['echo'] }, policy(), {
            homeDir: '/home/user',
            cwd: '/work',
        });
        expect(args).toContain('--dev');
        expect(args[args.indexOf('--dev') + 1]).toBe('/dev');
        expect(args).toContain('--proc');
        expect(args[args.indexOf('--proc') + 1]).toBe('/proc');
    });

    it('binds readable roots with --ro-bind', () => {
        const args = buildBubblewrapArgs(
            { argv: ['ls'] },
            policy({ readableRoots: ['/opt/data'] }, {}),
            { homeDir: '/home/user', cwd: '/work' },
        );
        // Expect a --ro-bind /opt/data /opt/data pair (or /work /work + /opt/data /opt/data)
        const bindCount = args.filter((a) => a === '--ro-bind').length;
        expect(bindCount).toBeGreaterThanOrEqual(2); // cwd + /opt/data + platform defaults
    });

    it('binds writable roots with --bind and readOnlySubpaths with --ro-bind', () => {
        const args = buildBubblewrapArgs(
            { argv: ['ls'] },
            policy(
                {
                    mode: 'workspaceWrite',
                    writableRoots: [{ path: '/work', readOnlySubpaths: ['.git'] }],
                },
                {},
            ),
            { homeDir: '/home/user', cwd: '/work' },
        );
        // --bind /work /work
        expect(args).toContain('--bind');
        expect(args[args.indexOf('--bind') + 1]).toBe('/work');
        // The .git subpath must end up as a --ro-bind /work/.git /work/.git
        // pair SOMEWHERE in the arg list.
        const idx = args.indexOf('--ro-bind', args.indexOf('--bind'));
        expect(idx).toBeGreaterThan(0);
        expect(args[idx + 1]).toBe('/work/.git');
        expect(args[idx + 2]).toBe('/work/.git');
    });

    it('adds --unshare-net for restricted network', () => {
        const args = buildBubblewrapArgs(
            { argv: ['echo'] },
            policy({}, { mode: 'restricted' }),
            { homeDir: '/home/user', cwd: '/work' },
        );
        expect(args).toContain('--unshare-net');
    });

    it('does not add --unshare-net for open network', () => {
        const args = buildBubblewrapArgs(
            { argv: ['echo'] },
            policy({}, {}),
            { homeDir: '/home/user', cwd: '/work' },
        );
        expect(args).not.toContain('--unshare-net');
    });

    it('always includes --die-with-parent --new-session for safety', () => {
        const args = buildBubblewrapArgs({ argv: ['echo'] }, policy(), {
            homeDir: '/home/user',
            cwd: '/work',
        });
        expect(args).toContain('--die-with-parent');
        expect(args).toContain('--new-session');
    });

    it('overlays hardcoded deny paths with --tmpfs when covered', () => {
        // cwd is /home/user, so /home/user/.git is covered
        const args = buildBubblewrapArgs({ argv: ['echo'] }, policy(), {
            homeDir: '/home/user',
            cwd: '/home/user',
        });
        // Look for "--tmpfs /home/user/.git" or similar
        const tmpfsIdx = args.indexOf('--tmpfs', 1);
        const tmpfsPaths: string[] = [];
        for (let i = tmpfsIdx; i < args.length; i += 2) {
            if (args[i] === '--tmpfs' && args[i + 1] && args[i + 1] !== '/') {
                tmpfsPaths.push(args[i + 1]);
            }
        }
        // Should include .git overlay
        expect(tmpfsPaths).toContain('/home/user/.git');
    });
});
