// Contract test for the `logging` module: it logs the calls of the sp-jwt-test routes with a replayable fake backend
// (no live backend is involved: the logger only observes the client's own HTTP calls).
import { describe, expect, it } from 'vitest';
import { createJwtAuth, memoryStore, presets, userSession } from '../../src';
import type { AuthLogEntry } from '../../src';
import { createAuthLogger } from '../../src/logging';

describe('logging contract', () => {
  it('logs the login call of the preset routes with fixed fields only', async () => {
    const entries: AuthLogEntry[] = [];
    const fetchFake = (async () =>
      new Response(JSON.stringify({ token: { access_token: 'a.b.c', refresh_token: 'r', expires_in: 900, token_type: 'Bearer' } }), {
        status: 200,
        headers: { 'Content-Type': 'application/json', 'X-Request-Id': 'req-1' },
      })) as unknown as typeof fetch;
    const auth = createJwtAuth({
      baseUrl: 'https://api.example.com',
      ...presets.spJwtTest,
      mode: userSession({ storage: memoryStore(), crossTab: false }),
      fetch: fetchFake,
      logger: createAuthLogger({ sink: (e) => entries.push(e) }),
      logRequests: true,
    });
    await auth.login({ email: 'ada@example.com', password: 'secret-password' });
    expect(entries).toHaveLength(1);
    expect(Object.keys(entries[0]!).sort()).toEqual(['attempt', 'code', 'durationMs', 'errorCode', 'method', 'path', 'requestId', 'status']);
    expect(entries[0]).toMatchObject({ method: 'POST', status: 200, requestId: 'req-1', code: null });
    expect(JSON.stringify(entries)).not.toContain('secret-password');
    auth.dispose?.();
  });
});
