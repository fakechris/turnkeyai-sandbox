/**
 * Windows setup-state persistence.
 *
 * Tracks whether the user has run `turnkeyai-sandbox setup-windows` (which
 * provisions a dedicated sandbox user + firewall rules). When the version
 * of `setup-state.json` is older than {@link SETUP_VERSION}, we ask the
 * user to re-run setup.
 *
 * @public
 */

import { readFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { safeJsonParse } from '../../util/safe-json.js';

/** Bump when the setup-state schema changes. */
export const SETUP_VERSION = 1;

/** Persisted setup state. */
export interface SetupState {
    version: number;
    installedAt: number;
    sid: string;
}

/** Path to setup-state.json. */
export function getSetupStatePath(): string {
    return join(process.env.LOCALAPPDATA ?? '', 'turnkeyai-sandbox', 'setup-state.json');
}

/** Read the persisted state, or null on failure. */
export function readSetupState(): SetupState | null {
    try {
        const raw = readFileSync(getSetupStatePath(), 'utf8');
        const parsed: SetupState | null = safeJsonParse<SetupState | null>(raw, null);
        return parsed;
    } catch {
        return null;
    }
}

/** Persist setup state, creating parent directories as needed. */
export function writeSetupState(state: SetupState): void {
    const filePath = getSetupStatePath();
    mkdirSync(dirname(filePath), { recursive: true });
    writeFileSync(filePath, JSON.stringify(state, null, 2), 'utf8');
}

/** True when setup has never been run, or the persisted state is older than the current schema. */
export function isSetupRequired(): boolean {
    const state = readSetupState();
    if (state === null) {
        return true;
    }
    return state.version < SETUP_VERSION;
}

/** True only when the persisted state matches the current SETUP_VERSION exactly. */
export function isSetupVersionMatch(): boolean {
    const state = readSetupState();
    if (state === null) {
        return false;
    }
    return state.version === SETUP_VERSION;
}
