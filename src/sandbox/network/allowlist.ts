/**
 * Domain allowlist normalization and validation.
 *
 * Reverse-engineered from
 * `packages/sandbox/src/network/allowlist.ts` .
 *
 * Rejects dangerous wildcard patterns (e.g. `*.com`) but accepts legitimate
 * exact hosts, `*.example.com` subdomain wildcards, and IPv4/IPv6 literals.
 *
 * @public
 */

/** Top-level TLDs that must not be used as wildcard TLDs. */
const DANGEROUS_TLDS: ReadonlySet<string> = new Set([
    'com',
    'net',
    'org',
    'edu',
    'gov',
    'io',
    'co',
    'dev',
    'app',
    'me',
    'info',
    'biz',
    'us',
    'uk',
    'cn',
    'ru',
    'de',
    'fr',
    'jp',
    'au',
    'in',
    'br',
    'it',
    'nl',
    'se',
    'no',
    'fi',
    'dk',
    'kr',
    'tw',
    'hk',
    'sg',
    'za',
    'mx',
    'ar',
    'cl',
    'pl',
    'cz',
    'at',
    'ch',
    'be',
    'pt',
    'es',
    'ie',
    'nz',
    'xyz',
]);

/** Expose the dangerous TLD set (read-only) for tests and tooling. @public */
export function getDangerousTlds(): ReadonlySet<string> {
    return DANGEROUS_TLDS;
}

/** A rejected allowlist entry with its reason. */
export interface RejectedHost {
    host: string;
    reason: string;
}

/** Result of {@link normalizeAllowedHosts}. */
export interface NormalizeResult {
    normalized: string[];
    rejected: RejectedHost[];
}

/**
 * Normalize an array of allowed-host entries.
 *
 * - Lowercases and trims
 * - Rejects: empty string, NUL bytes, bare `*` / `*.*`, TLD-level wildcards
 *   against {@link DANGEROUS_TLDS}, pure integer strings (port misuse), IPv6
 *   zone-IDs (`fe80::1%eth0`)
 *
 * Reverse-engineered from.
 *
 * @public
 */
export function normalizeAllowedHosts(hosts: readonly string[]): NormalizeResult {
    const normalized: string[] = [];
    const rejected: RejectedHost[] = [];
    for (const raw of hosts) {
        // Empty string
        if (raw === '') {
            rejected.push({ host: raw, reason: 'empty string' });
            continue;
        }
        // NUL byte
        if (raw.includes('\0')) {
            rejected.push({ host: raw, reason: 'contains nul byte' });
            continue;
        }
        const lower = raw.toLowerCase().trim();
        // Bare wildcard
        if (lower === '*' || lower === '*.*') {
            rejected.push({ host: raw, reason: 'overly broad wildcard' });
            continue;
        }
        // TLD-level wildcard: *.com, *.net, etc.
        const tldWildcardMatch = /^\*\.([a-z0-9]+)$/.exec(lower);
        if (tldWildcardMatch) {
            const tld = tldWildcardMatch[1] ?? '';
            if (DANGEROUS_TLDS.has(tld)) {
                rejected.push({
                    host: raw,
                    reason: `top-level TLD wildcard *.${tld} is too broad`,
                });
                continue;
            }
        }
        // Integer IP (possible port misuse): pure digits like "12345"
        if (/^\d+$/.test(lower)) {
            rejected.push({ host: raw, reason: 'looks like integer IP or port number' });
            continue;
        }
        // IPv6 zone-ID (contains %)
        if (lower.includes('%')) {
            rejected.push({ host: raw, reason: 'IPv6 zone-ID not allowed' });
            continue;
        }
        normalized.push(lower);
    }
    return { normalized, rejected };
}

/**
 * Check whether `target` matches any entry in `allowedHosts`.
 *
 * Supports exact match and `*.example.com` wildcard subdomains.
 * Reverse-engineered from.
 *
 * @public
 */
export function hostAllowed(target: string, allowedHosts: readonly string[]): boolean {
    const lower = target.toLowerCase();
    for (const entry of allowedHosts) {
        if (entry === lower) {
            return true;
        }
        // Wildcard subdomain: *.example.com matches foo.example.com
        if (entry.startsWith('*.')) {
            const suffix = entry.slice(1); // ".example.com"
            if (lower.endsWith(suffix) || lower === entry.slice(2)) {
                return true;
            }
        }
    }
    return false;
}
