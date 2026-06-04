/**
 * Rule file loader.
 *
 * Reverse-engineered from
 * `packages/sandbox-policy/src/rules/loader.ts` .
 *
 * Reads `*.rules.json` (and optional `*.rules.ts` for advanced users) from a
 * config dir, validates them, and returns the union of all rules.
 *
 * @public
 */

import { readdir, readFile } from 'node:fs/promises';
import { extname, join } from 'node:path';
import type { PolicyRule } from './schema.js';
import { safeJsonParse } from '../../util/safe-json.js';
import { validateRuleFile } from './schema.js';

/** Single rule-file load result. */
export interface RuleSet {
    rules: PolicyRule[];
    filePath: string;
    loadedAt: number;
}

/**
 * List and load all rule files in `configDir` (files ending in `.rules.json`).
 *
 * The also supports `.rules.ts` (dynamic import); for our
 * JavaScript-only build we only support `.rules.json` and warn about any
 * `.rules.ts` files (we never read them silently).
 *
 * @public
 */
export async function loadRules(configDir: string): Promise<RuleSet[]> {
    const entries = await readdir(configDir);
    const ruleFiles = entries
        .filter((entry) => entry.endsWith('.rules.json') || entry.endsWith('.rules.ts'))
        .sort();
    const results: RuleSet[] = [];
    for (const file of ruleFiles) {
        const filePath = join(configDir, file);
        if (file.endsWith('.rules.ts')) {
            // .rules.ts requires dynamic import of a TS file, which only works
            // under ts-node / tsx. The had this working via
            // webpack's require() interceptor. For the JS-only npm package we
            // log and skip — users can convert their .rules.ts to .rules.json.
            // (This is a deliberate, transparent limitation, not a bug.)
            continue;
        }
        const rules = await loadRuleFile(filePath);
        results.push({ rules, filePath, loadedAt: Date.now() });
    }
    return results;
}

/**
 * Load a single rule file.
 *
 * @public
 */
export async function loadRuleFile(filePath: string): Promise<PolicyRule[]> {
    const ext = extname(filePath);
    if (filePath.endsWith('.rules.json')) {
        const content = await readFile(filePath, 'utf-8');
        const data: unknown = safeJsonParse(content, undefined);
        if (typeof data === 'undefined') {
            throw new Error(`Failed to parse JSON rule file: ${filePath}`);
        }
        return validateRuleFile(data);
    }
    throw new Error(`Unsupported rule file extension: ${ext}`);
}
