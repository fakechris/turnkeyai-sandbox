/**
 * Rule persistence + banned-prefix table.
 *
 * Reverse-engineered from
 * `packages/sandbox-policy/src/rules/persistence.ts` .
 *
 * The `BANNED_RULE_PREFIXES` table is verbatim from the — these
 * are explicit anti-bypass patterns and must not be user-overridable.
 *
 * @public
 */

import { readFile, writeFile, mkdir, rename } from 'node:fs/promises';
import { dirname } from 'node:path';
import type { PatternElement, PolicyRule, PrefixRule } from './schema.js';
import { safeJsonParse } from '../../util/safe-json.js';
import { validateRuleFile } from './schema.js';

/**
 * Banned prefix table. The wires this into `appendAllowPrefixRule`
 * so the engine physically refuses to "approve" a banned prefix even if the
 * user interface lets the user click approve.
 *
 * Each entry is a `string[]` (the argv prefix that must not be allowed).
 *
 * @public
 */
export const BANNED_RULE_PREFIXES: readonly (readonly string[])[] = Object.freeze([
    Object.freeze(['bash']),
    Object.freeze(['bash', '-lc']),
    Object.freeze(['bash', '-c']),
    Object.freeze(['sh']),
    Object.freeze(['sh', '-c']),
    Object.freeze(['sh', '-lc']),
    Object.freeze(['zsh']),
    Object.freeze(['zsh', '-lc']),
    Object.freeze(['zsh', '-c']),
    Object.freeze(['/bin/bash']),
    Object.freeze(['/bin/bash', '-lc']),
    Object.freeze(['/bin/sh']),
    Object.freeze(['/bin/sh', '-c']),
    Object.freeze(['/bin/zsh']),
    Object.freeze(['/bin/zsh', '-lc']),
    Object.freeze(['node']),
    Object.freeze(['node', '-e']),
    Object.freeze(['python']),
    Object.freeze(['python', '-c']),
    Object.freeze(['python3']),
    Object.freeze(['python3', '-c']),
    Object.freeze(['ruby']),
    Object.freeze(['ruby', '-e']),
    Object.freeze(['perl']),
    Object.freeze(['perl', '-e']),
    Object.freeze(['php']),
    Object.freeze(['php', '-r']),
    Object.freeze(['lua']),
    Object.freeze(['lua', '-e']),
    Object.freeze(['sudo']),
    Object.freeze(['su']),
    Object.freeze(['doas']),
    Object.freeze(['env']),
    Object.freeze(['osascript']),
    Object.freeze(['pwsh']),
    Object.freeze(['pwsh', '-Command']),
    Object.freeze(['pwsh', '-c']),
    Object.freeze(['powershell']),
    Object.freeze(['powershell', '-Command']),
    Object.freeze(['powershell', '-c']),
]);

/**
 * Returns true if `prefix` exactly matches any entry in `BANNED_RULE_PREFIXES`.
 *
 *:
 * ```js
 * BANNED_RULE_PREFIXES.some((banned) =>
 *     banned.length === prefix.length &&
 *     banned.every((b, i) => b === prefix[i])
 * )
 * ```
 *
 * @public
 */
export function isBannedPrefix(prefix: readonly string[]): boolean {
    return BANNED_RULE_PREFIXES.some(
        (banned) => banned.length === prefix.length && banned.every((b, i) => b === prefix[i]),
    );
}

/**
 * Append an `allow` prefix rule to a rule file, atomically.
 *
 * - Refuses to add banned prefixes (security boundary)
 * - Dedups against existing identical rules
 * - Validates the resulting file as `PolicyRule[]` before writing
 * - Atomic: write to a temp file then rename
 *
 * Reverse-engineered from.
 *
 * @public
 */
export async function appendAllowPrefixRule(
    filePath: string,
    prefix: PatternElement[],
): Promise<void> {
    if (isBannedPrefix(prefix as string[])) {
        throw new Error(
            `Prefix [${prefix.map((p) => (Array.isArray(p) ? p.join('|') : p)).join(', ')}] is banned and cannot be added as an allow rule`,
        );
    }
    let existing: PolicyRule[] = [];
    try {
        const content = await readFile(filePath, 'utf-8');
        const parsed: unknown = safeJsonParse(content, undefined);
        if (typeof parsed === 'undefined') {
            throw new Error(`Failed to parse rule file: ${filePath}`);
        }
        if (!Array.isArray(parsed)) {
            throw new Error(`Rule file is not a JSON array: ${filePath}`);
        }
        existing = validateRuleFile(parsed);
    } catch (err) {
        const isNotFound =
            typeof err === 'object' &&
            err !== null &&
            'code' in err &&
            (err as { code: unknown }).code === 'ENOENT';
        if (!isNotFound) {
            throw err;
        }
    }
    const newRule: PrefixRule = {
        kind: 'prefix',
        pattern: prefix,
        decision: 'allow',
    };
    // Dedup: skip if an identical rule already exists
    const isDuplicate = existing.some(
        (rule) =>
            rule.kind === 'prefix' &&
            rule.decision === 'allow' &&
            JSON.stringify(rule.pattern) === JSON.stringify(prefix),
    );
    if (isDuplicate) {
        return;
    }
    existing.push(newRule);
    // Validate the full array
    validateRuleFile(existing);
    // Ensure parent directory exists
    const dir = dirname(filePath);
    await mkdir(dir, { recursive: true });
    // Atomic write: write to temp file, then rename
    const tmpFile = `${filePath}.tmp.${Date.now()}`;
    await writeFile(tmpFile, JSON.stringify(existing, null, 2), 'utf-8');
    await rename(tmpFile, filePath);
}
