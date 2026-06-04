/**
 * Public surface of the command policy layer.
 * Reverse-engineered from `packages/sandbox-policy/src/command/index.ts`.
 *
 * @public
 */

export {
    EXECUTABLE_EXTENSION_RE,
    getCommandBasename,
    normalizeCommandName,
} from './common.js';

export {
    getShellWrapInfo,
    isShellWrapped,
    parseCommand,
    tokenizeShellString,
    tokenizePowerShellString,
    tokenizeCmdString,
} from './parser.js';
export type { ShellWrapInfo } from './parser.js';

export {
    classifyCommand,
    isSafeCommand,
    isDangerousCommand,
} from './classifier.js';

export { extractCommandPathAccesses, analyzeCommand } from './analyzer.js';
