import { describe, expect, it } from 'vitest';
import { safeJsonParse, safeJsonParseOrThrow } from '../../../src/util/safe-json.js';

describe('safeJsonParse', () => {
    it('parses valid JSON', () => {
        expect(safeJsonParse('{"a":1}', {})).toEqual({ a: 1 });
    });

    it('returns defaultValue for invalid JSON', () => {
        expect(safeJsonParse('not json', { fallback: true })).toEqual({ fallback: true });
    });

    it('returns defaultValue for non-string input', () => {
        expect(safeJsonParse(undefined, 'fallback')).toBe('fallback');
        expect(safeJsonParse(42, 'fallback')).toBe('fallback');
        expect(safeJsonParse(null, 'fallback')).toBe('fallback');
        expect(safeJsonParse({}, 'fallback')).toBe('fallback');
    });

    it('returns defaultValue for empty string', () => {
        expect(safeJsonParse('', 'fallback')).toBe('fallback');
    });

    it('applies reviver when given', () => {
        const out = safeJsonParse<unknown>(
            '{"a":1,"b":2}',
            {},
            { reviver: (_k, v) => (typeof v === 'number' ? v * 10 : v) },
        );
        expect(out).toEqual({ a: 10, b: 20 });
    });
});

describe('safeJsonParseOrThrow', () => {
    it('parses valid JSON', () => {
        expect(safeJsonParseOrThrow<{ a: number }>('{"a":1}')).toEqual({ a: 1 });
    });

    it('throws on invalid input', () => {
        expect(() => safeJsonParseOrThrow('not json')).toThrow();
        expect(() => safeJsonParseOrThrow(undefined)).toThrow();
        expect(() => safeJsonParseOrThrow(42)).toThrow();
    });
});
