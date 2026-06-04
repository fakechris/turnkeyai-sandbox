import { describe, expect, it } from 'vitest';
import { getPlatform, tryGetPlatform } from '../../../src/util/platform.js';

describe('getPlatform', () => {
    it('returns one of the three supported platforms on this host', () => {
        const p = getPlatform();
        expect(['darwin', 'linux', 'win32']).toContain(p);
    });

    it('matches process.platform', () => {
        expect(getPlatform()).toBe(process.platform);
    });
});

describe('tryGetPlatform', () => {
    it('returns the same as getPlatform on supported hosts', () => {
        expect(tryGetPlatform()).toBe(getPlatform());
    });
});
