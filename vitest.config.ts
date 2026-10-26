import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    projects: [
      { test: { name: 'node', environment: 'node', include: ['test/**/*.test.ts'] } },
      {
        // Edge runtime (@edge-runtime/vm): proves the code under test runs with the edge VM's web globals (fetch,
        // Request/Response, crypto.subtle, streams...). It does NOT prove the absence of Node-only code: vitest copies
        // the edge globals onto the Node worker's global, so `process`, `Buffer` and `setImmediate` stay visible.
        // Those are guarded elsewhere: test/acceptance/globals.node.test.ts (AST scan of src/ for Node and browser
        // globals), scripts/check-dist.mjs and scripts/check-bundle.mjs (`node:` and bare built-in imports in dist and
        // in browser bundles). test/edge-canary.test.ts proves this project really runs in the edge environment.
        test: {
          name: 'edge',
          environment: 'edge-runtime',
          include: ['test/**/*.test.ts'],
          exclude: ['test/**/*.contract.test.ts', 'test/**/*.node.test.ts', 'test/node/**', 'test/support/**', 'test/verify/verify.test.ts'],
        },
      },
    ],
  },
});
