import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    projects: [
      { test: { name: 'node', environment: 'node', include: ['test/**/*.test.ts'] } },
      {
        // Browser-like runtime: proves src/ has no Node-only dependency.
        test: {
          name: 'edge',
          environment: 'edge-runtime',
          include: ['test/**/*.test.ts'],
          exclude: ['test/**/*.contract.test.ts', 'test/node/**', 'test/support/**'],
        },
      },
    ],
  },
});
