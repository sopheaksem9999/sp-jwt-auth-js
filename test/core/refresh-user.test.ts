import { describe, expect, it } from 'vitest';
import { createJwtAuth, userSession } from '../../src/core/create-jwt-auth';
import { memoryStore } from '../../src/core/stores';

// R2 parity: a token refresh must keep getState().user (whoami fills it; the
// documented refresh response carries no user).

function b64url(s: string): string {
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
const now = (): number => Math.floor(Date.now() / 1000);
function jwt(payload: Record<string, unknown>): string {
  return `${b64url('{"alg":"none","typ":"JWT"}')}.${b64url(JSON.stringify(payload))}.sig`;
}
function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

const ada = { id: 7, name: 'Ada', email: 'ada@example.com' };
const loginAccess = jwt({ sub: '7', exp: now() + 900, jti: 'login' });
const refreshedAccess = jwt({ sub: '7', exp: now() + 900, jti: 'rotated' });

// Documented refresh shape (token-endpoints guide): no user.
const refreshBody = {
  access_token: refreshedAccess,
  refresh_token: 'r2',
  token_type: 'Bearer',
  expires_in: 900,
};

type Handler = { refresh: () => Response };

async function loggedInWithUser(h: Handler) {
  const store = memoryStore();
  const urls: string[] = [];
  const fetchFn = (async (input: RequestInfo | URL): Promise<Response> => {
    const url = String(input);
    urls.push(url);
    if (url.endsWith('/auth/login')) {
      return json({ access_token: loginAccess, refresh_token: 'r1', token_type: 'Bearer', expires_in: 900 });
    }
    if (url.endsWith('/auth/whoami')) return json(ada);
    if (url.endsWith('/auth/refresh')) return h.refresh();
    return json({}, 404);
  }) as typeof fetch;
  const auth = createJwtAuth({
    baseUrl: 'https://api.example.com/',
    endpoints: { login: '/auth/login', refresh: '/auth/refresh', whoami: '/auth/whoami' },
    mode: userSession({ storage: store }),
    fetch: fetchFn,
  });
  await auth.login({ email: 'ada@example.com', password: 'p' });
  expect(await auth.whoami()).toEqual(ada);
  expect(auth.getState().user).toEqual(ada);
  return { auth, store, urls };
}

describe('refresh keeps getState().user (R2)', () => {
  it('keeps the whoami user when the refresh response has no user', async () => {
    const { auth, store, urls } = await loggedInWithUser({ refresh: () => json(refreshBody) });
    await auth.refresh();
    expect(urls.filter((u) => u.endsWith('/auth/refresh'))).toHaveLength(1);
    expect((await store.get())?.accessToken).toBe(refreshedAccess);
    const s = auth.getState();
    expect(s.status).toBe('authenticated');
    expect(s.user).toEqual(ada);
    expect(s.claims?.jti).toBe('rotated');
    const persisted = await store.get();
    expect(persisted).not.toHaveProperty('user');
    expect(Object.keys(persisted ?? {})).not.toContain('user');
  });

  it('ignores a user field in the refresh response: state user stays the whoami user, nothing is persisted', async () => {
    const grace = { id: 99, name: 'Grace' };
    const { auth, store } = await loggedInWithUser({ refresh: () => json({ ...refreshBody, user: grace }) });
    await auth.refresh();
    expect(auth.getState().status).toBe('authenticated');
    expect(auth.getState().user).toEqual(ada);
    expect(await store.get()).not.toHaveProperty('user');
    expect((await store.get())?.refreshToken).toBe('r2');
  });

  it('keeps the user when the refresh fails transiently (5xx)', async () => {
    const { auth, store } = await loggedInWithUser({ refresh: () => json({ message: 'down' }, 503) });
    await expect(auth.refresh()).rejects.toBeDefined();
    expect(auth.getState().status).toBe('authenticated');
    expect(auth.getState().user).toEqual(ada);
    expect((await store.get())?.refreshToken).toBe('r1');
  });
});
