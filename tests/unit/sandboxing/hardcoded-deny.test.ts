import { describe, expect, it } from 'vitest';
import {
    HARDCODED_DENY_PATHS,
    checkHardcodedDenyOverlap,
    checkPathAgainstDenyList,
    resolveAnchors,
} from '../../../src/sandbox/sandboxing/hardcoded-deny.js';

describe('HARDCODED_DENY_PATHS', () => {
    it('contains 8 verbatim entries', () => {
        expect(HARDCODED_DENY_PATHS).toEqual([
            '.git',
            '.ssh',
            '.codex',
            '.agents',
            '.gnupg',
            '.aws/credentials',
            '.config/gcloud',
            '.kube/config',
        ]);
    });
});

describe('resolveAnchors', () => {
    it('resolves against home and cwd', () => {
        const anchors = resolveAnchors('.ssh', '/home/user', '/work');
        expect(anchors).toContain('/home/user/.ssh');
        expect(anchors).toContain('/work/.ssh');
    });

    it('returns one anchor when home and cwd resolve to the same place', () => {
        const anchors = resolveAnchors('.ssh', '/tmp', '/tmp');
        expect(anchors).toEqual(['/tmp/.ssh']);
    });
});

describe('checkHardcodedDenyOverlap', () => {
    it('returns empty when writable roots do not overlap any deny path', () => {
        const result = checkHardcodedDenyOverlap(
            [{ path: '/var/tmp' }],
            '/home/user',
            '/work',
        );
        expect(result).toEqual([]);
    });

    it('returns overlapping deny entries', () => {
        const result = checkHardcodedDenyOverlap(
            [{ path: '/home/user' }],
            '/home/user',
            '/work',
        );
        expect(result).toContain('.git');
        expect(result).toContain('.ssh');
    });

    it('refuses when writable root is the deny path itself', () => {
        const result = checkHardcodedDenyOverlap(
            [{ path: '/home/user/.ssh' }],
            '/home/user',
            '/work',
        );
        expect(result).toContain('.ssh');
    });
});

describe('checkPathAgainstDenyList', () => {
    it('returns the deny entry when an exact match hits', () => {
        const hits = checkPathAgainstDenyList(['/home/user/.ssh/id_rsa'], '/home/user', '/work');
        expect(hits).toContain('.ssh');
    });

    it('returns the deny entry when a subpath hits', () => {
        const hits = checkPathAgainstDenyList(['/home/user/.git/HEAD'], '/home/user', '/work');
        expect(hits).toContain('.git');
    });

    it('returns empty when no path hits', () => {
        const hits = checkPathAgainstDenyList(['/var/tmp/foo'], '/home/user', '/work');
        expect(hits).toEqual([]);
    });
});
