/**
 * User command shape (the argv envelope passed to `runInSandbox`).
 *
 * Reverse-engineered from
 * `packages/sandbox/src/protocol/user-command.ts` .
 *
 * @public
 */

export interface UserCommand {
    argv: string[];
    env?: Record<string, string>;
    cwd?: string;
}

export function isUserCommand(v: unknown): v is UserCommand {
    if (typeof v !== 'object' || v === null) {
        return false;
    }
    const r = v as Record<string, unknown>;
    if (!Array.isArray(r.argv) || !(r.argv as unknown[]).every((x) => typeof x === 'string')) {
        return false;
    }
    if (r.env !== undefined) {
        if (typeof r.env !== 'object' || r.env === null) {
            return false;
        }
        for (const [, v] of Object.entries(r.env as Record<string, unknown>)) {
            if (typeof v !== 'string') {
                return false;
            }
        }
    }
    if (r.cwd !== undefined && typeof r.cwd !== 'string') {
        return false;
    }
    return true;
}
