import { describe, expect, it } from 'vitest';

// Canary for the vitest `edge` project (spec §7 runtime matrix): proves the edge project really runs its files in
// the @edge-runtime/vm environment, so a misconfigured project (environment dropped or changed) cannot silently run
// the "edge" suite in plain Node. `pnpm test:edge-canary` runs this file with `--project edge` only, which also
// fails ("No test files found") if the edge project stops including test files.
//
// Why `EdgeRuntime` and not `process` / `require`: vitest's edge-runtime environment copies the edge VM globals
// onto the Node worker's global, so `process`, `Buffer` and `setImmediate` stay visible and `require` is
// undefined in every ESM test file in both projects (probed on vitest 5.0.3 + @edge-runtime/vm 5.0.0). Only the
// `EdgeRuntime` global, which the edge VM defines and Node never does, tells the two apart. The guard against
// Node built-ins in shipped code is therefore check-dist.mjs / check-bundle.mjs, not this project.
const g = globalThis as { EdgeRuntime?: unknown; process?: { versions?: { node?: string } } };

describe('edge canary', () => {
  it('runs in the environment its project name claims', ({ task }) => {
    const project = task.file.projectName;
    expect(['node', 'edge']).toContain(project);
    if (project === 'edge') {
      expect(g.EdgeRuntime).toBe('edge-runtime');
    } else {
      expect(g.EdgeRuntime).toBeUndefined();
      expect(typeof g.process?.versions?.node).toBe('string');
    }
  });

  it('edge only: the web platform globals come from the edge VM', ({ task }) => {
    if (task.file.projectName !== 'edge') return;
    for (const name of ['fetch', 'Request', 'Response', 'Headers', 'URL', 'TextEncoder', 'crypto', 'ReadableStream', 'AbortController']) {
      expect(typeof (globalThis as Record<string, unknown>)[name], name).not.toBe('undefined');
    }
    expect(typeof crypto.subtle.importKey).toBe('function');
  });
});
