import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
    resolve: {
        alias: {
            '@turnkeyai/sandbox': resolve(here, 'src/index.ts'),
        },
    },
    test: {
        globals: false,
        environment: 'node',
        include: [
            'tests/unit/**/*.test.ts',
            'tests/integration/**/*.test.ts',
            'tests/e2e/**/*.test.ts',
        ],
        // Default to unit + integration; e2e runs separately via npm run test:e2e
        testTimeout: 30_000,
        hookTimeout: 30_000,
        coverage: {
            provider: 'v8',
            reporter: ['text', 'html', 'json'],
            include: ['src/**/*.ts'],
            exclude: ['src/**/*.d.ts', 'src/cli/**', 'src/version.ts'],
            thresholds: {
                lines: 80,
                branches: 70,
                functions: 80,
                statements: 80,
            },
        },
    },
});
