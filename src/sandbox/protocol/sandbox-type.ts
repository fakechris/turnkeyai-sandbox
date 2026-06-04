/**
 * Sandbox type enum.
 *
 * Reverse-engineered from
 * `packages/sandbox/src/protocol/sandbox-type.ts` .
 *
 * @public
 */

export type SandboxType =
    | 'macosSeatbelt'
    | 'linuxBubblewrap'
    | 'windowsRestrictedToken'
    | 'windowsElevated'
    | 'none';

export const SANDBOX_TYPES: readonly SandboxType[] = [
    'macosSeatbelt',
    'linuxBubblewrap',
    'windowsRestrictedToken',
    'windowsElevated',
    'none',
] as const;

export function isSandboxType(v: unknown): v is SandboxType {
    return (
        v === 'macosSeatbelt' ||
        v === 'linuxBubblewrap' ||
        v === 'windowsRestrictedToken' ||
        v === 'windowsElevated' ||
        v === 'none'
    );
}
