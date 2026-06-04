/**
 * Sandbox-specific errors.
 *
 * Reverse-engineered from
 * `packages/sandbox/src/protocol/errors.ts` .
 *
 * @public
 */

/**
 * Thrown when a requested sandbox backend is not available on the host
 * (e.g. WindowsRestrictedToken on Linux).
 */
export class SandboxUnsupportedError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'SandboxUnsupportedError';
    }
}
