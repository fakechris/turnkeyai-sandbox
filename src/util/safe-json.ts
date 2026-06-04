/**
 * safe-json helpers used in many places (loader, persistence, log-stream).
 *
 * Reverse-engineered from `packages/sandbox/src/util/safe-json.ts` (
 * bundle line 42400-ish, used inline in many modules). The two-arg form
 * returns the default value on parse failure; the three-arg form additionally
 * takes a parse-options object.
 *
 * @public
 */
export interface SafeJsonParseOptions {
    /** Forwarded to `JSON.parse` reviver. */
    reviver?: (key: string, value: unknown) => unknown;
}

/**
 * Parse a JSON string safely, returning `defaultValue` on failure.
 *
 * @param input         The (possibly invalid) JSON string.
 * @param defaultValue  Returned when `input` is empty, not a string, or fails to parse.
 * @param options       Optional JSON.parse reviver.
 * @public
 */
export function safeJsonParse<T = unknown>(
    input: unknown,
    defaultValue: T,
    options?: SafeJsonParseOptions,
): T {
    if (typeof input !== 'string' || input.length === 0) {
        return defaultValue;
    }
    try {
        return JSON.parse(input, options?.reviver) as T;
    } catch {
        return defaultValue;
    }
}

/**
 * Strict form that throws on parse failure. Useful when invalid JSON is
 * a programming error rather than a recoverable runtime condition.
 * @public
 */
export function safeJsonParseOrThrow<T = unknown>(
    input: unknown,
    options?: SafeJsonParseOptions,
): T {
    if (typeof input !== 'string' || input.length === 0) {
        throw new TypeError('safeJsonParseOrThrow: input is not a non-empty string');
    }
    return JSON.parse(input, options?.reviver) as T;
}
