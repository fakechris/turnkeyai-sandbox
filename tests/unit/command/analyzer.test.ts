import { describe, expect, it } from 'vitest';
import { analyzeCommand, extractCommandPathAccesses } from '../../../src/policy/command/analyzer.js';

describe('extractCommandPathAccesses', () => {
    it('extracts paths from a simple cat', () => {
        const out = extractCommandPathAccesses(['cat', 'file.txt']);
        expect(out).toEqual([{ path: 'file.txt', kind: 'read', command: ['cat', 'file.txt'] }]);
    });

    it('extracts paths from rm', () => {
        const out = extractCommandPathAccesses(['rm', 'a', 'b']);
        expect(out).toHaveLength(2);
        expect(out[0]?.kind).toBe('delete');
        expect(out[1]?.kind).toBe('delete');
    });

    it('extracts paths from cp (last is write, others are read)', () => {
        const out = extractCommandPathAccesses(['cp', 'src', 'dst']);
        expect(out).toHaveLength(2);
        expect(out[0]).toMatchObject({ path: 'src', kind: 'read' });
        expect(out[1]).toMatchObject({ path: 'dst', kind: 'write' });
    });

    it('extracts paths from mv (move_source, move_target)', () => {
        const out = extractCommandPathAccesses(['mv', 'src', 'dst']);
        expect(out[0]).toMatchObject({ kind: 'move_source' });
        expect(out[1]).toMatchObject({ kind: 'move_target' });
    });

    it('extracts paths from mkdir', () => {
        const out = extractCommandPathAccesses(['mkdir', 'foo']);
        expect(out[0]).toMatchObject({ kind: 'create' });
    });

    it('extracts paths from touch', () => {
        const out = extractCommandPathAccesses(['touch', 'foo']);
        expect(out[0]).toMatchObject({ kind: 'create' });
    });

    it('extracts paths from redirection >', () => {
        // includes BOTH the positional read of "out.txt" AND the explicit
        // write from ">" — duplicates are by design.
        const out = extractCommandPathAccesses(['ls', '>', 'out.txt']);
        expect(out).toHaveLength(3);
        expect(out.find((o) => o.kind === 'write')).toMatchObject({ path: 'out.txt' });
    });

    it('extracts paths from redirection <', () => {
        const out = extractCommandPathAccesses(['cat', '<', 'in.txt']);
        // Both the positional read and the explicit "<" read appear.
        const reads = out.filter((o) => o.kind === 'read' && o.path === 'in.txt');
        expect(reads.length).toBeGreaterThanOrEqual(1);
    });

    it('extracts paths from redirection 2> (file-descriptor prefix)', () => {
        const out = extractCommandPathAccesses(['ls', '2>', 'err.log']);
        const writes = out.filter((o) => o.kind === 'write' && o.path === 'err.log');
        expect(writes.length).toBeGreaterThanOrEqual(1);
    });

    it('extracts paths from redirection >> (append)', () => {
        const out = extractCommandPathAccesses(['ls', '>>', 'out.txt']);
        const writes = out.filter((o) => o.kind === 'write' && o.path === 'out.txt');
        expect(writes.length).toBeGreaterThanOrEqual(1);
    });

    it('decomposes shell-wrapped command and extracts from each sub-command', () => {
        // produces both positional and redirection entries for each
        // sub-command — duplicates included.
        const out = extractCommandPathAccesses(['bash', '-c', 'cat a > b']);
        expect(out.length).toBeGreaterThanOrEqual(2);
        const reads = out.filter((o) => o.path === 'a' && o.kind === 'read');
        const writes = out.filter((o) => o.path === 'b' && o.kind === 'write');
        expect(reads.length).toBeGreaterThanOrEqual(1);
        expect(writes.length).toBeGreaterThanOrEqual(1);
    });

    it('skips options when extracting positional paths', () => {
        const out = extractCommandPathAccesses(['rm', '-v', '--', 'a', 'b']);
        expect(out.map((o) => o.path)).toEqual(['a', 'b']);
    });

    it('returns [] for unknown commands', () => {
        expect(extractCommandPathAccesses(['curl', 'https://example.com'])).toEqual([]);
    });

    it('extracts PowerShell -Path and -LiteralPath', () => {
        const out = extractCommandPathAccesses(['Remove-Item', '-Path', 'foo.txt', '-Recurse']);
        expect(out[0]).toMatchObject({ path: 'foo.txt', kind: 'delete' });
    });

    it('handles PowerShell Copy-Item with -Path and -Destination', () => {
        const out = extractCommandPathAccesses([
            'Copy-Item',
            '-Path',
            'a.txt',
            '-Destination',
            'b.txt',
        ]);
        expect(out).toHaveLength(2);
        expect(out[0]).toMatchObject({ kind: 'read' });
        expect(out[1]).toMatchObject({ kind: 'write' });
    });
});

describe('analyzeCommand', () => {
    it('produces subCommands, classifications, and pathAccesses', () => {
        const out = analyzeCommand(['bash', '-c', 'ls && rm -rf /tmp']);
        expect(out.subCommands).toEqual([['ls'], ['rm', '-rf', '/tmp']]);
        expect(out.classifications).toHaveLength(2);
        expect(out.classifications[0]?.safety).toBe('safe');
        expect(out.classifications[1]?.safety).toBe('dangerous');
        expect(out.pathAccesses.length).toBeGreaterThan(0);
    });
});
