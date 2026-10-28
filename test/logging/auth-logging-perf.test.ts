import { describe, expect, it } from 'vitest';
import type { AuthLogEntry } from '../../src';
import { createAuthLogger } from '../../src/logging';

// Every entry is built inline on the request path: the cost must stay linear in the input length.
function entry(baseUrl: string, endpoint: string, requestId: unknown): { e: AuthLogEntry; ms: number } {
  let e: AuthLogEntry | undefined;
  const call = createAuthLogger({ sink: (x) => void (e = x) }).start({ method: 'GET', baseUrl, endpoint, signal: undefined });
  const t0 = performance.now();
  call?.finish({ body: { meta: { request_id: requestId } }, response: new Response('{}', { status: 200 }) });
  return { e: e as AuthLogEntry, ms: performance.now() - t0 };
}

function timedStart(baseUrl: string, endpoint: string): number {
  const t0 = performance.now();
  createAuthLogger({ sink: () => {} }).start({ method: 'GET', baseUrl, endpoint, signal: undefined });
  return performance.now() - t0;
}

const N = 100_000;

describe('request logging performance (100k-character inputs, under 250 ms each)', () => {
  it('a baseUrl with a long run of slashes inside', () => {
    const base = `https://api.example.com/a${'/'.repeat(N)}b`;
    expect(timedStart(base, '/x')).toBeLessThan(250);
    expect(timedStart(`https://api.example.com/a${'/'.repeat(N)}`, '/x')).toBeLessThan(250);
  });

  it('long paths, query runs and spaces', () => {
    for (const endpoint of [`/${'a'.repeat(N)}`, `/x${'?'.repeat(N)}`, `/a${' '.repeat(N)}b`, `/${'%20'.repeat(N)}`]) {
      expect(timedStart('https://api.example.com', endpoint)).toBeLessThan(250);
    }
  });

  it('long request ids', () => {
    for (const id of [`${' '.repeat(N)}x${' '.repeat(N)}`, `${'\u0000'.repeat(N)}x`, '😀'.repeat(N), `a${' '.repeat(N)}b`]) {
      const { e, ms } = entry('https://api.example.com', '/x', id);
      expect(ms).toBeLessThan(250);
      expect([...(e.requestId ?? '')].length).toBeLessThanOrEqual(128);
    }
  });

  it('keeps the trailing-slash trimming of the baseUrl', () => {
    expect(entry('https://api.example.com/api///', 'auth/login', 'r').e.path).toBe('/api/auth/login');
  });
});
