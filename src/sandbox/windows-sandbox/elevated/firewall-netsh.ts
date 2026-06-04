/**
 * Windows Firewall helpers (netsh advfirewall).
 *
 * Reverse-engineered from
 * `packages/sandbox-exec/src/windows-sandbox/elevated/firewall-netsh.ts`.
 *
 * Each sandbox user gets a per-SID outbound block rule. When a
 * `proxyPort` is configured, an additional allow rule for the proxy
 * port is added (allow rules take precedence over block rules when
 * more specific in Windows Firewall).
 *
 * Per Coze §14.5: firewall management is done via the `netsh` CLI
 * rather than COM — `netsh` is shipped with every Windows install and
 * is stable across versions.
 *
 * @public
 */

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

/** Add a single netsh firewall rule. */
async function addFirewallRule(opts: {
    ruleName: string;
    sid: string;
    direction: 'in' | 'out';
    action: 'block' | 'allow';
    allowedPort?: number;
}): Promise<void> {
    const args = [
        'advfirewall',
        'firewall',
        'add',
        'rule',
        `name=${opts.ruleName}`,
        `dir=${opts.direction}`,
        `action=${opts.action}`,
        'protocol=any',
        'enable=yes',
        `localuser=${opts.sid}`,
    ];
    if (opts.allowedPort !== undefined) {
        args.push('protocol=tcp', `remoteport=${opts.allowedPort}`);
    }
    await execFileAsync('netsh', args);
}

/** Remove a firewall rule by name. */
async function removeFirewallRule(ruleName: string): Promise<void> {
    await execFileAsync('netsh', [
        'advfirewall',
        'firewall',
        'delete',
        'rule',
        `name=${ruleName}`,
    ]);
}

/** Firewall setup result with cleanup. */
export interface FirewallSetup {
    /** Rule names that were added — useful for diagnostics. */
    ruleNames: string[];
    cleanup: () => Promise<void>;
}

/**
 * Set up firewall rules for a sandbox user: deny all outbound by SID,
 * optionally allow a specific proxy port.
 *
 * @public
 */
export async function setupSandboxFirewall(
    sid: string,
    proxyPort?: number,
): Promise<FirewallSetup> {
    const ruleNames: string[] = [];
    const blockRuleName = `turnkeyai-sandbox-block-out-${sid}`;
    await addFirewallRule({
        ruleName: blockRuleName,
        sid,
        action: 'block',
        direction: 'out',
    });
    ruleNames.push(blockRuleName);
    if (proxyPort !== undefined) {
        const allowRuleName = `turnkeyai-sandbox-allow-proxy-${sid}`;
        await addFirewallRule({
            ruleName: allowRuleName,
            sid,
            action: 'allow',
            direction: 'out',
            allowedPort: proxyPort,
        });
        ruleNames.push(allowRuleName);
    }
    return {
        ruleNames,
        cleanup: async () => {
            for (const name of ruleNames) {
                try {
                    await removeFirewallRule(name);
                } catch {
                    // best-effort: rule may already be gone
                }
            }
        },
    };
}
