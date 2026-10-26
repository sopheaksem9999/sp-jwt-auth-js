import { afterEach, describe, expect, it, vi } from 'vitest';
import { readCookie } from '../../src/core/cookie';
import { createJwtAuth, userSession } from '../../src/core/create-jwt-auth';
import type { AuthEvent, JwtAuth, UserSessionOptions } from '../../src/core/create-jwt-auth';
import { createCrossTab } from '../../src/core/crosstab';
import type { CrossTab } from '../../src/core/crosstab';
import { SpAuthError } from '../../src/core/errors';
import { memoryStore, webStorageStore } from '../../src/core/stores';
import type { TokenStore, Tokens } from '../../src/core/stores';
import * as api from '../../src/index';

// Cookie transport (spec §4.3): the refresh token is an httpOnly cookie the client never sees,
// the access token lives in memory, storage keeps only csrf/deviceId/lastCompanyId.

function b64url(s: string): string {
  let bin = '';
  for (const b of new TextEncoder().encode(s)) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function jwt(payload: Record<string, unknown>): string {
  return `${b64url(JSON.stringify({ alg: 'none', typ: 'JWT' }))}.${b64url(JSON.stringify(payload))}.sig`;
}

const now = (): number => Math.floor(Date.now() / 1000);

/** A refresh-token literal the backend's `both` mode returns in the body; it must never be held anywhere. */
const RT = 'rt-cookie-secret-9f1c2e7d-never-held';

const nearExpiry = jwt({ sub: '7', exp: now() + 30 });
const fresh1 = jwt({ sub: '7', exp: now() + 900 });
const fresh2 = jwt({ sub: '7', exp: now() + 1800, company_id: 5 });
const otherUser = jwt({ sub: '8', exp: now() + 900 });

/** A token response as the backend's `both` mode sends it: the body still carries `refresh_token`. */
function pairBody(access: string): Record<string, unknown> {
  return { user: { id: 7 }, token: { access_token: access, refresh_token: RT, expires_in: 900, token_type: 'Bearer' } };
}

function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } });
}

interface Call {
  method: string;
  path: string;
  headers: Headers;
  body: string | undefined;
  credentials: RequestCredentials | undefined;
}

type Handler = (c: Call) => Response | Promise<Response>;

function fakeFetch(handler: Handler): { fetch: typeof fetch; calls: Call[] } {
  const calls: Call[] = [];
  const f = (async (input: string | URL, init?: RequestInit): Promise<Response> => {
    const c: Call = {
      method: init?.method ?? 'GET',
      path: new URL(String(input)).pathname,
      headers: new Headers(init?.headers),
      body: typeof init?.body === 'string' ? init.body : undefined,
      credentials: init?.credentials,
    };
    calls.push(c);
    return handler(c);
  }) as unknown as typeof fetch;
  return { fetch: f, calls };
}

const endpoints = { login: '/auth/login', whoami: '/me', switchCompany: '/auth/impersonate_in' };

interface Setup {
  auth: JwtAuth;
  store: TokenStore;
  calls: Call[];
  events: AuthEvent[];
}

function setup(handler: Handler, opts: UserSessionOptions = {}, extra: { device?: { id?: string } } = {}): Setup {
  const store = opts.storage ?? memoryStore();
  const { fetch, calls } = fakeFetch(handler);
  const events: AuthEvent[] = [];
  const auth = createJwtAuth({
    baseUrl: 'https://api.example.com',
    endpoints,
    mode: userSession({ crossTab: false, ...opts, storage: store, transport: 'cookie' }),
    fetch,
    onEvent: (e) => events.push(e),
    ...extra,
  });
  return { auth, store, calls, events };
}

/** Everything a script could reach after the fact, serialised, for a "the refresh token is not here" scan. */
async function reachable(s: Setup, extra: unknown[] = []): Promise<string> {
  return JSON.stringify([await s.store.get(), s.auth.getState(), s.events, ...extra]);
}

function expectOnlyNonSecret(t: Tokens | null): void {
  for (const k of Object.keys(t ?? {})) expect(['csrf', 'deviceId', 'lastCompanyId']).toContain(k);
  expect(t).not.toHaveProperty('accessToken');
  expect(t).not.toHaveProperty('refreshToken');
}

function stubDocument(cookie: string): void {
  vi.stubGlobal('document', { cookie });
}

async function flush(): Promise<void> {
  for (let i = 0; i < 40; i++) await Promise.resolve();
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('readCookie', () => {
  it('returns null without a document', () => {
    expect(typeof (globalThis as { document?: unknown }).document).toBe('undefined');
    expect(readCookie('sp_csrf')).toBeNull();
  });

  it('finds the named cookie exactly and URL-decodes it', () => {
    stubDocument('xsp_csrf=nope; a=1; sp_csrf=abc%3D%3D;  other=2');
    expect(readCookie('sp_csrf')).toBe('abc==');
    expect(readCookie('a')).toBe('1');
    expect(readCookie('missing')).toBeNull();
  });

  it('returns the raw value when it is not valid URL encoding, and null when document.cookie throws', () => {
    stubDocument('sp_csrf=%E0%A4%A');
    expect(readCookie('sp_csrf')).toBe('%E0%A4%A');
    vi.stubGlobal('document', {
      get cookie(): string {
        throw new Error('SecurityError');
      },
    });
    expect(readCookie('sp_csrf')).toBeNull();
  });

  it('is exported from the package root', () => {
    expect(api.readCookie).toBe(readCookie);
  });
});

describe('cookie transport: login', () => {
  it("uses credentials:'include', drops the body refresh_token, keeps the access token in memory only", async () => {
    stubDocument('sp_csrf=from-cookie');
    const s = setup(() => json(pairBody(fresh1), 200, { 'X-SP-CSRF': 'from-header' }), {}, { device: {} });
    const res = await s.auth.login({ email: 'a@b.c', password: 'x' });

    expect(res).toEqual({ status: 'authenticated' });
    expect(s.calls[0]!.credentials).toBe('include');
    expect(s.auth.getState().status).toBe('authenticated');
    expect(await s.auth.getHeaders()).toEqual({ Authorization: `Bearer ${fresh1}` });

    const stored = await s.store.get();
    expectOnlyNonSecret(stored);
    // csrf: the response header wins over the readable cookie
    expect(stored?.csrf).toBe('from-header');
    expect(stored?.deviceId).toEqual(expect.any(String));
    expect(await reachable(s)).not.toContain(RT);
    expect(JSON.stringify(await s.store.get())).not.toContain(fresh1);
  });

  it('falls back to readCookie(sp_csrf) when the response has no X-SP-CSRF header', async () => {
    stubDocument('theme=dark; sp_csrf=c%2Bv');
    const s = setup(() => json(pairBody(fresh1)));
    await s.auth.login({});
    expect((await s.store.get())?.csrf).toBe('c+v');
  });

  it('honours custom csrf header and cookie names', async () => {
    stubDocument('my_csrf=cookie-val');
    const s = setup(() => json(pairBody(fresh1), 200, { 'X-My-Csrf': 'hdr-val' }), { csrf: { header: 'X-My-Csrf', cookie: 'my_csrf' } });
    await s.auth.login({});
    expect((await s.store.get())?.csrf).toBe('hdr-val');
  });

  it('the second-factor step also uses credentials and captures the csrf header', async () => {
    const { fetch, calls } = fakeFetch((c) =>
      c.path === '/auth/login'
        ? json({ requires_2fa: true, '2fa_token': 'tfa' })
        : json(pairBody(fresh1), 200, { 'X-SP-CSRF': 'csrf-2fa' }),
    );
    const store = memoryStore();
    const auth = createJwtAuth({
      baseUrl: 'https://api.example.com',
      endpoints: { login: '/auth/login', secondFactor: '/auth/login/2fa' },
      mode: userSession({ storage: store, transport: 'cookie', crossTab: false }),
      fetch,
    });
    const r = await auth.login({});
    if (r.status !== 'second_factor_required') throw new Error('expected a challenge');
    await auth.verifySecondFactor(r.challenge, '123456');
    expect(calls.map((c) => c.credentials)).toEqual(['include', 'include']);
    expect((await store.get())?.csrf).toBe('csrf-2fa');
    expectOnlyNonSecret(await store.get());
  });
});

describe('cookie transport: refresh', () => {
  it('sends no body token, includes credentials, echoes X-SP-CSRF, persists the rotated csrf', async () => {
    const s = setup((c) =>
      c.path === '/auth/login'
        ? json(pairBody(nearExpiry), 200, { 'X-SP-CSRF': 'csrf-1' })
        : json({ access_token: fresh2, refresh_token: RT, expires_in: 900, token_type: 'Bearer' }, 200, { 'X-SP-CSRF': 'csrf-2' }),
    );
    await s.auth.login({});
    // proactive: the login token is inside the refresh-ahead window
    expect(await s.auth.getAccessToken()).toBe(fresh2);

    const r = s.calls[1]!;
    expect(r.path).toBe('/auth/token/refresh');
    expect(r.method).toBe('POST');
    expect(r.credentials).toBe('include');
    expect(r.body).toBeUndefined();
    expect(r.headers.get('X-SP-CSRF')).toBe('csrf-1');
    expect(r.headers.get('Authorization')).toBeNull();

    const stored = await s.store.get();
    expectOnlyNonSecret(stored);
    expect(stored?.csrf).toBe('csrf-2');
    expect(s.auth.getState().companyId).toBe('5');
    expect(s.events.map((e) => e.type)).toEqual(['login', 'refresh']);
    expect(await reachable(s)).not.toContain(RT);
  });

  it('a refresh 401 while signed in ends the session (csrf cleared, deviceId kept)', async () => {
    const s = setup((c) => (c.path === '/auth/login' ? json(pairBody(fresh1), 200, { 'X-SP-CSRF': 'c1' }) : json({ message: 'x' }, 401)));
    await s.store.set({ deviceId: 'd1' });
    await s.auth.login({});
    const err = await s.auth.refresh().catch((e: unknown) => e);
    expect((err as SpAuthError).code).toBe('session_ended');
    expect(s.auth.getState().status).toBe('anonymous');
    expect(await s.store.get()).toEqual({ deviceId: 'd1' });
    expect(s.events.map((e) => e.type)).toEqual(['login', 'refresh_failed', 'session_ended']);
    expect(await s.auth.getAccessToken()).toBeNull();
  });

  it('a refresh 403 is csrf_failed and does not end the session', async () => {
    const s = setup((c) =>
      c.path === '/auth/login' ? json(pairBody(fresh1), 200, { 'X-SP-CSRF': 'c1' }) : json({ message: 'CSRF token mismatch.' }, 403),
    );
    await s.auth.login({});
    const err = await s.auth.refresh().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(SpAuthError);
    expect((err as SpAuthError).code).toBe('csrf_failed');
    expect((err as SpAuthError).status).toBe(403);
    expect(s.auth.getState().status).toBe('authenticated');
    expect((await s.store.get())?.csrf).toBe('c1');
    expect(s.events.map((e) => e.type)).not.toContain('session_ended');
    // the header was seen on the login response, so this is a mismatch, not a CORS exposure problem
    expect((err as SpAuthError).message).not.toContain('exposed_headers');
  });

  it('handleUnauthorized refreshes once and resolves true; false when nothing is held', async () => {
    const s = setup((c) =>
      c.path === '/auth/login'
        ? json(pairBody(fresh1), 200, { 'X-SP-CSRF': 'c1' })
        : json({ access_token: fresh2, expires_in: 900, token_type: 'Bearer' }, 200, { 'X-SP-CSRF': 'c2' }),
    );
    expect(await s.auth.handleUnauthorized()).toBe(false);
    expect(s.calls).toHaveLength(0);
    await s.auth.login({});
    expect(await s.auth.handleUnauthorized({ headers: { Authorization: `Bearer ${fresh1}` } })).toBe(true);
    expect(await s.auth.getAccessToken()).toBe(fresh2);
    // a stale bearer: a refresh already happened, no request
    expect(await s.auth.handleUnauthorized({ headers: { Authorization: `Bearer ${fresh1}` } })).toBe(true);
    expect(s.calls.map((c) => c.path)).toEqual(['/auth/login', '/auth/token/refresh']);
  });
});

describe('cookie transport: restore()', () => {
  it('calls refresh once with the stored csrf and becomes authenticated', async () => {
    const store = memoryStore();
    await store.set({ csrf: 'stored-csrf', deviceId: 'd1' });
    const s = setup(() => json({ access_token: fresh1, refresh_token: RT, expires_in: 900, token_type: 'Bearer' }, 200, { 'X-SP-CSRF': 'next' }), {
      storage: store,
    });
    expect(s.auth.getState().status).toBe('unknown');
    await s.auth.restore();
    expect(s.calls).toHaveLength(1);
    expect(s.calls[0]!.path).toBe('/auth/token/refresh');
    expect(s.calls[0]!.headers.get('X-SP-CSRF')).toBe('stored-csrf');
    expect(s.calls[0]!.credentials).toBe('include');
    expect(s.auth.getState().status).toBe('authenticated');
    expect(await store.get()).toEqual({ csrf: 'next', deviceId: 'd1' });
    // a second restore() with a session in memory makes no request
    await s.auth.restore();
    expect(s.calls).toHaveLength(1);
    expect(await reachable(s)).not.toContain(RT);
  });

  it('a 401 means "not logged in": anonymous, no error, no session_ended noise', async () => {
    const store = memoryStore();
    await store.set({ csrf: 'old', deviceId: 'd1' });
    const s = setup(() => json({ message: 'Unauthenticated.' }, 401), { storage: store });
    await expect(s.auth.restore()).resolves.toBeUndefined();
    expect(s.calls).toHaveLength(1);
    expect(s.auth.getState().status).toBe('anonymous');
    expect(s.events.map((e) => e.type)).not.toContain('session_ended');
    expect(s.events.map((e) => e.type)).not.toContain('refresh_failed');
    expect(await store.get()).toEqual({ deviceId: 'd1' });
  });

  it('with no csrf value at all it is anonymous without calling fetch', async () => {
    stubDocument('theme=dark');
    const s = setup(() => json({}, 500));
    await s.auth.restore();
    expect(s.calls).toHaveLength(0);
    expect(s.auth.getState().status).toBe('anonymous');
    expect(s.events).toEqual([]);
  });

  it('uses readCookie when the store has no csrf (same-site after storage was cleared)', async () => {
    stubDocument('sp_csrf=cookie-csrf');
    const s = setup(() => json({ access_token: fresh1, expires_in: 900, token_type: 'Bearer' }));
    await s.auth.restore();
    expect(s.calls[0]!.headers.get('X-SP-CSRF')).toBe('cookie-csrf');
    expect(s.auth.getState().status).toBe('authenticated');
  });

  it('a 403 on a stored value rejects csrf_failed with a neutral message and leaves the state unchanged', async () => {
    const store = memoryStore();
    await store.set({ csrf: 'stale' });
    const s = setup(() => json({ message: 'CSRF token mismatch.' }, 403), { storage: store });
    const err = await s.auth.restore().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(SpAuthError);
    expect((err as SpAuthError).code).toBe('csrf_failed');
    expect((err as SpAuthError).status).toBe(403);
    // a stored value was sent: a mismatch, not a CORS exposure problem (even right after a reload)
    expect((err as SpAuthError).message).not.toContain('exposed_headers');
    expect((err as SpAuthError).message).toContain('does not match');
    expect((err as SpAuthError).message).toContain('reload');
    expect(s.calls).toHaveLength(1); // no document: no retry
    expect(s.auth.getState().status).toBe('unknown');
    expect(await store.get()).toEqual({ csrf: 'stale' });
    expect(s.events.map((e) => e.type)).not.toContain('session_ended');
  });

  it('a refresh 403 with no value ever obtained (header hidden cross-site) carries the exposed_headers hint', async () => {
    // login response without X-SP-CSRF and no readable cookie: what a cross-site API without exposed_headers looks like
    const s = setup((c) => (c.path === '/auth/login' ? json(pairBody(fresh1)) : json({ message: 'CSRF token mismatch.' }, 403)));
    await s.auth.login({});
    const err = await s.auth.refresh().catch((e: unknown) => e);
    expect((err as SpAuthError).code).toBe('csrf_failed');
    expect(s.calls[1]!.headers.get('X-SP-CSRF')).toBeNull();
    expect((err as SpAuthError).message).toContain('exposed_headers');
    expect((err as SpAuthError).message).toContain('X-SP-CSRF');
    expect(s.auth.getState().status).toBe('authenticated');
  });

  it('a login that lands while restore() is in flight is not wiped by its 401 (no tab context)', async () => {
    const store = memoryStore();
    await store.set({ csrf: 'old' });
    let releaseRefresh!: (r: Response) => void;
    const s = setup(
      (c) =>
        c.path === '/auth/login'
          ? json(pairBody(fresh1), 200, { 'X-SP-CSRF': 'c-login' })
          : new Promise<Response>((r) => (releaseRefresh = r)),
      { storage: store },
    );
    const restoring = s.auth.restore();
    await flush();
    await s.auth.login({});
    releaseRefresh(json({ message: 'Unauthenticated.' }, 401));
    await expect(restoring).resolves.toBeUndefined();
    expect(s.auth.getState().status).toBe('authenticated');
    expect(await s.auth.getAccessToken()).toBe(fresh1);
    expect((await store.get())?.csrf).toBe('c-login');
    expect(s.events.map((e) => e.type)).not.toContain('session_ended');
  });

  it('csrf: false skips the header and the no-value shortcut', async () => {
    const s = setup(() => json({ access_token: fresh1, expires_in: 900, token_type: 'Bearer' }), { csrf: false });
    await s.auth.restore();
    expect(s.calls).toHaveLength(1);
    expect(s.calls[0]!.headers.get('X-SP-CSRF')).toBeNull();
    expect(s.auth.getState().status).toBe('authenticated');
  });

  it('is ready() for the body transport', async () => {
    const { fetch, calls } = fakeFetch(() => json({}, 500));
    const auth = createJwtAuth({ baseUrl: 'https://api.example.com', endpoints, mode: userSession({ storage: memoryStore() }), fetch });
    await auth.restore();
    expect(auth.getState().status).toBe('anonymous');
    expect(calls).toHaveLength(0);
  });

  it('scrubs tokens a former body-transport session left in the store', async () => {
    const store = memoryStore();
    await store.set({ accessToken: fresh1, refreshToken: RT, expiresAt: now() + 900, csrf: 'c', deviceId: 'd' });
    const s = setup(() => json({}, 401), { storage: store });
    await s.auth.ready();
    expect(await store.get()).toEqual({ csrf: 'c', deviceId: 'd' });
  });
});

describe('cookie transport: stale stored csrf recovers from the readable cookie', () => {
  it('refresh: on 403 the live sp_csrf cookie is stored and the request retried once', async () => {
    const store = memoryStore();
    await store.set({ csrf: 'old' });
    stubDocument('sp_csrf=new%2Bone'); // another tab (private store, no channel) rotated it
    let n = 0;
    const s = setup(
      () => (++n === 1 ? json({ message: 'CSRF token mismatch.' }, 403) : json({ access_token: fresh1, expires_in: 900, token_type: 'Bearer' }, 200, { 'X-SP-CSRF': 'after' })),
      { storage: store },
    );
    await s.auth.restore();
    expect(s.calls.map((c) => c.headers.get('X-SP-CSRF'))).toEqual(['old', 'new+one']);
    expect(s.auth.getState().status).toBe('authenticated');
    expect((await store.get())?.csrf).toBe('after');
    expect(s.events.map((e) => e.type)).toEqual(['refresh']);
  });

  it('retries only once: a second 403 is csrf_failed', async () => {
    const store = memoryStore();
    await store.set({ csrf: 'old' });
    stubDocument('sp_csrf=new');
    const s = setup(() => json({ message: 'CSRF token mismatch.' }, 403), { storage: store });
    const err = await s.auth.restore().catch((e: unknown) => e);
    expect((err as SpAuthError).code).toBe('csrf_failed');
    expect(s.calls).toHaveLength(2);
    expect(s.auth.getState().status).toBe('unknown');
  });

  it('no retry when the cookie is absent or equal to the value sent', async () => {
    for (const cookie of ['theme=dark', 'sp_csrf=old']) {
      const store = memoryStore();
      await store.set({ csrf: 'old' });
      stubDocument(cookie);
      const s = setup(() => json({ message: 'CSRF token mismatch.' }, 403), { storage: store });
      const err = await s.auth.restore().catch((e: unknown) => e);
      expect((err as SpAuthError).code).toBe('csrf_failed');
      expect(s.calls).toHaveLength(1);
    }
  });

  it('revoke: a 403 is retried once with the live cookie, and nothing is stored afterwards', async () => {
    stubDocument('');
    let revokes = 0;
    const s = setup((c) => {
      if (c.path === '/auth/login') return json(pairBody(fresh1), 200, { 'X-SP-CSRF': 'c1' });
      return ++revokes === 1 ? json({ message: 'CSRF token mismatch.' }, 403) : new Response(null, { status: 204 });
    });
    await s.store.set({ deviceId: 'd1' });
    await s.auth.login({});
    stubDocument('sp_csrf=c9');
    await s.auth.logout();
    expect(s.calls.slice(1).map((c) => [c.path, c.headers.get('X-SP-CSRF')])).toEqual([
      ['/auth/token/revoke', 'c1'],
      ['/auth/token/revoke', 'c9'],
    ]);
    expect(s.events[s.events.length - 1]).toEqual({ type: 'logout', everywhere: false });
    expect(await s.store.get()).toEqual({ deviceId: 'd1' });
  });

  it('switchCompany: a 403 is retried once with the live cookie', async () => {
    stubDocument('');
    let switches = 0;
    const s = setup((c) => {
      if (c.path === '/auth/login') return json(pairBody(fresh1), 200, { 'X-SP-CSRF': 'c1' });
      return ++switches === 1
        ? json({ message: 'CSRF token mismatch.' }, 403)
        : json({ access_token: fresh2, expires_in: 900, token_type: 'Bearer' }, 200, { 'X-SP-CSRF': 'c3' });
    });
    await s.auth.login({});
    stubDocument('sp_csrf=c9');
    await s.auth.switchCompany(5);
    expect(s.calls.slice(1).map((c) => c.headers.get('X-SP-CSRF'))).toEqual(['c1', 'c9']);
    expect(s.auth.getState().companyId).toBe('5');
    expect((await s.store.get())?.csrf).toBe('c3');
  });

  it('switchCompany: no retry without a document', async () => {
    const s = setup((c) =>
      c.path === '/auth/login' ? json(pairBody(fresh1), 200, { 'X-SP-CSRF': 'c1' }) : json({ message: 'CSRF token mismatch.' }, 403),
    );
    await s.auth.login({});
    const err = await s.auth.switchCompany(5).catch((e: unknown) => e);
    expect((err as SpAuthError).status).toBe(403);
    expect(s.calls).toHaveLength(2);
    expect(s.auth.getState().claims?.sub).toBe('7');
  });
});

describe('cookie transport: server runtime (no document)', () => {
  it('fetch → 401: restore() resolves, state anonymous, nothing thrown', async () => {
    const store = memoryStore();
    await store.set({ csrf: 'injected' });
    const s = setup(() => json({ message: 'Unauthenticated.' }, 401), { storage: store });
    await expect(s.auth.restore()).resolves.toBeUndefined();
    expect(s.auth.getState().status).toBe('anonymous');
    expect(await s.auth.getHeaders()).toEqual({});
  });

  it('defaults (memory store, default crossTab): no fetch, no channel, no lock', async () => {
    const constructed: string[] = [];
    const request = vi.fn();
    vi.stubGlobal('navigator', { locks: { request } });
    vi.stubGlobal(
      'BroadcastChannel',
      class {
        constructor(name: string) {
          constructed.push(name);
        }
      },
    );
    const { fetch, calls } = fakeFetch(() => json({}, 401));
    const auth = createJwtAuth({ baseUrl: 'https://api.example.com', endpoints, mode: userSession({ transport: 'cookie' }), fetch });
    await auth.restore();
    expect(auth.getState().status).toBe('anonymous');
    expect(calls).toHaveLength(0);
    expect(constructed).toEqual([]);
    expect(request).not.toHaveBeenCalled();
  });
});

describe('cookie transport: logout', () => {
  it('sends the bearer AND the cookie with X-SP-CSRF, clears csrf, keeps deviceId', async () => {
    const s = setup((c) => (c.path === '/auth/login' ? json(pairBody(fresh1), 200, { 'X-SP-CSRF': 'c1' }) : new Response(null, { status: 204 })));
    await s.store.set({ deviceId: 'd1' });
    await s.auth.login({});
    await s.auth.logout();
    const r = s.calls[1]!;
    expect(r.path).toBe('/auth/token/revoke');
    expect(r.method).toBe('POST');
    expect(r.headers.get('Authorization')).toBe(`Bearer ${fresh1}`);
    expect(r.headers.get('X-SP-CSRF')).toBe('c1');
    expect(r.credentials).toBe('include');
    expect(await s.store.get()).toEqual({ deviceId: 'd1' });
    expect(s.auth.getState().status).toBe('anonymous');
    expect(s.events[s.events.length - 1]).toEqual({ type: 'logout', everywhere: false });
  });

  it('treats 401 as already logged out, and revokes by cookie alone when no access token is held', async () => {
    const store = memoryStore();
    await store.set({ csrf: 'c-only' });
    const s = setup(() => json({ message: 'Unauthenticated.' }, 401), { storage: store });
    await s.auth.logout();
    expect(s.calls).toHaveLength(1);
    expect(s.calls[0]!.headers.get('Authorization')).toBeNull();
    expect(s.calls[0]!.headers.get('X-SP-CSRF')).toBe('c-only');
    expect(s.calls[0]!.credentials).toBe('include');
    expect(s.events).toEqual([{ type: 'logout', everywhere: false }]);
    expect(s.auth.getState().status).toBe('anonymous');
  });

  it('uses the host endpoints.logout when configured', async () => {
    const { fetch, calls } = fakeFetch((c) =>
      c.path === '/auth/login' ? json(pairBody(fresh1), 200, { 'X-SP-CSRF': 'c1' }) : new Response(null, { status: 204 }),
    );
    const auth = createJwtAuth({
      baseUrl: 'https://api.example.com',
      endpoints: { login: '/auth/login', logout: '/auth/logout' },
      mode: userSession({ transport: 'cookie', crossTab: false }),
      fetch,
    });
    await auth.login({});
    await auth.logout({ everywhere: true });
    expect(calls[1]!.path).toBe('/auth/logout');
    expect(calls[1]!.body).toBe(JSON.stringify({ everywhere: true }));
    expect(calls[1]!.headers.get('X-SP-CSRF')).toBe('c1');
  });
});

describe('cookie transport: switchCompany and whoami', () => {
  it('switchCompany omits refresh_token, includes credentials and X-SP-CSRF, persists lastCompanyId only', async () => {
    const s = setup(
      (c) =>
        c.path === '/auth/login'
          ? json(pairBody(fresh1), 200, { 'X-SP-CSRF': 'c1' })
          : json({ access_token: fresh2, refresh_token: RT, expires_in: 900, token_type: 'Bearer' }, 200, { 'X-SP-CSRF': 'c2' }),
      {},
      { device: { id: 'dev-1' } },
    );
    await s.auth.login({});
    await s.auth.switchCompany(5);
    const r = s.calls[1]!;
    expect(r.path).toBe('/auth/impersonate_in');
    expect(JSON.parse(r.body!)).toEqual({ company_id: 5 });
    expect(r.body).not.toContain('refresh_token');
    expect(r.credentials).toBe('include');
    expect(r.headers.get('X-SP-CSRF')).toBe('c1');
    expect(r.headers.get('X-Device-Id')).toBe('dev-1');
    expect(r.headers.get('Authorization')).toBe(`Bearer ${fresh1}`);
    expect(s.auth.getState().companyId).toBe('5');
    const stored = await s.store.get();
    expectOnlyNonSecret(stored);
    expect(stored).toMatchObject({ csrf: 'c2', lastCompanyId: '5' });
    expect(await reachable(s)).not.toContain(RT);
  });

  it('whoami does not attach a user when the subject changed while it was in flight', async () => {
    let releaseMe!: (r: Response) => void;
    const s = setup((c) => {
      if (c.path === '/me') return new Promise<Response>((r) => (releaseMe = r));
      const sub8 = c.body?.includes('"u":"8"') === true;
      return json(pairBody(sub8 ? otherUser : fresh1), 200, { 'X-SP-CSRF': 'c' });
    });
    await s.auth.login({ u: '7' });
    const pending = s.auth.whoami();
    await flush();
    await s.auth.login({ u: '8' });
    releaseMe(json({ id: 7, name: 'Seven' }));
    expect(await pending).toEqual({ id: 7, name: 'Seven' });
    expect(s.auth.getState().claims?.sub).toBe('8');
    expect(s.auth.getState().user).toBeNull();

    // the same subject still attaches
    const again = s.auth.whoami();
    await flush();
    releaseMe(json({ id: 8 }));
    await again;
    expect(s.auth.getState().user).toEqual({ id: 8 });
  });
});

/**
 * In-memory `BroadcastChannel` bus: delivers to the other channels of the same name on a microtask.
 * With `held`, deliveries wait until `release()` (a message that arrives after a lock grant).
 */
class FakeBus {
  readonly open = new Set<FakeChannel>();
  readonly posted: unknown[] = [];
  held = false;
  private readonly pending: (() => void)[] = [];
  factory = (name: string): BroadcastChannel => new FakeChannel(this, name) as unknown as BroadcastChannel;
  deliver(run: () => void): void {
    if (this.held) this.pending.push(run);
    else queueMicrotask(run);
  }
  release(): void {
    this.held = false;
    for (const run of this.pending.splice(0)) queueMicrotask(run);
  }
}

class FakeChannel {
  readonly listeners = new Set<(e: { data: unknown }) => void>();
  constructor(
    private readonly bus: FakeBus,
    readonly name: string,
  ) {
    bus.open.add(this);
  }
  addEventListener(type: string, l: (e: { data: unknown }) => void): void {
    if (type === 'message') this.listeners.add(l);
  }
  removeEventListener(type: string, l: (e: { data: unknown }) => void): void {
    if (type === 'message') this.listeners.delete(l);
  }
  postMessage(data: unknown): void {
    const wire = JSON.stringify(data);
    this.bus.posted.push(JSON.parse(wire));
    for (const c of this.bus.open) {
      if (c === this || c.name !== this.name) continue;
      this.bus.deliver(() => {
        for (const l of [...c.listeners]) l({ data: JSON.parse(wire) });
      });
    }
  }
  close(): void {
    this.bus.open.delete(this);
  }
}

type LockCb = (lock: unknown) => Promise<unknown>;

/** Exclusive FIFO fake of `navigator.locks`, including `ifAvailable` (the probe gets `null` while the lock is busy). */
function fakeLocks(): { request(name: string, a: LockCb | { ifAvailable?: boolean }, b?: LockCb): Promise<unknown>; granted: string[] } {
  const tails = new Map<string, Promise<unknown>>();
  const busy = new Map<string, number>();
  const granted: string[] = [];
  return {
    granted,
    request(name, a, b) {
      const cb = (typeof a === 'function' ? a : b)!;
      if (typeof a === 'object' && a.ifAvailable === true && (busy.get(name) ?? 0) > 0) return Promise.resolve().then(() => cb(null));
      busy.set(name, (busy.get(name) ?? 0) + 1);
      const run = (tails.get(name) ?? Promise.resolve()).then(() => {
        granted.push(name);
        return cb({ name });
      });
      const tail = run.then(
        () => undefined,
        () => undefined,
      );
      void tail.then(() => busy.set(name, (busy.get(name) ?? 1) - 1));
      tails.set(name, tail);
      return run;
    },
  };
}

interface Tab extends Setup {
  crossTab: CrossTab;
}

function tab(
  bus: FakeBus,
  locks: ReturnType<typeof fakeLocks> | null,
  handler: Handler,
  store: TokenStore = memoryStore(),
  opts: UserSessionOptions = {},
): Tab {
  const crossTab = createCrossTab('app', { channel: bus.factory, locks, storageKey: null });
  const s = setup(handler, { ...opts, storage: store, crossTab: { instance: crossTab } });
  return { ...s, crossTab };
}

describe('cookie transport: tabs', () => {
  it("a login is broadcast (access token and csrf only) and the other tab follows", async () => {
    stubDocument('');
    const bus = new FakeBus();
    const locks = fakeLocks();
    const handler: Handler = () => json(pairBody(fresh1), 200, { 'X-SP-CSRF': 'c1' });
    const a = tab(bus, locks, handler);
    const b = tab(bus, locks, handler);
    await b.auth.ready(); // b listens
    await a.auth.login({});
    await flush();
    expect(b.auth.getState().status).toBe('authenticated');
    expect(await b.auth.getAccessToken()).toBe(fresh1);
    expect((await b.store.get())?.csrf).toBe('c1');
    expect(b.calls).toHaveLength(0);
    for (const m of bus.posted) {
      expect(Object.keys(m as object).sort()).toEqual(['accessToken', 'csrf', 'expiresAt', 'type']);
    }
    expect(JSON.stringify(bus.posted)).not.toContain(RT);
    // logout follows too, without a request from b
    await a.auth.logout();
    await flush();
    expect(b.auth.getState().status).toBe('anonymous');
    expect(b.calls).toHaveLength(0);
  });

  it("another tab's broadcast access token is used inside the lock when still fresh (one refresh in total)", async () => {
    stubDocument('');
    const bus = new FakeBus();
    const locks = fakeLocks();
    let refreshes = 0;
    const handler: Handler = (c) => {
      if (c.path === '/auth/login') return json(pairBody(nearExpiry), 200, { 'X-SP-CSRF': 'c1' });
      refreshes++;
      return json({ access_token: fresh2, refresh_token: RT, expires_in: 900, token_type: 'Bearer' }, 200, { 'X-SP-CSRF': 'c2' });
    };
    const a = tab(bus, locks, handler);
    const b = tab(bus, locks, handler);
    await b.auth.ready();
    await a.auth.login({});
    await flush();
    expect(b.auth.getState().status).toBe('authenticated');

    const [ta, tb] = await Promise.all([a.auth.getAccessToken(), b.auth.getAccessToken()]);
    expect(refreshes).toBe(1);
    expect(ta).toBe(fresh2);
    expect(tb).toBe(fresh2);
    expect(b.events).toContainEqual({ type: 'refresh', adopted: true });
    expect((await b.store.get())?.csrf).toBe('c2');
  });

  it("restore() in a tab that already received another tab's fresh token makes no request", async () => {
    stubDocument('');
    const bus = new FakeBus();
    const locks = fakeLocks();
    const b = tab(bus, locks, () => json({}, 500));
    await b.store.set({ csrf: 'c1' });
    await b.auth.ready();
    // another tab (not a session here, just its channel) broadcasts a fresh token
    const other = createCrossTab('app', { channel: bus.factory, locks, storageKey: null });
    other.broadcast({ type: 'tokens', accessToken: fresh1, expiresAt: now() + 900 });
    await flush();
    await b.auth.restore();
    expect(b.calls).toHaveLength(0);
    expect(b.auth.getState().status).toBe('authenticated');
  });

  it('reuse_suspected: a refresh 401 after another tab broadcast a newer token adopts it', async () => {
    stubDocument('');
    const bus = new FakeBus();
    const locks = fakeLocks();
    let release!: (r: Response) => void;
    const a = tab(bus, locks, (c) =>
      c.path === '/auth/login' ? json(pairBody(fresh1), 200, { 'X-SP-CSRF': 'c1' }) : new Promise<Response>((r) => (release = r)),
    );
    await a.auth.login({});
    const p = a.auth.refresh();
    await flush();
    // another tab rotated without our lock (e.g. no Web Locks) and broadcast its token
    const other = createCrossTab('app', { channel: bus.factory, locks: null, storageKey: null });
    other.broadcast({ type: 'tokens', accessToken: fresh2, expiresAt: now() + 1800, csrf: 'c2' });
    await flush();
    release(json({ message: 'reused' }, 401));
    await expect(p).resolves.toBeUndefined();
    expect(a.auth.getState().status).toBe('authenticated');
    expect(await a.auth.getAccessToken()).toBe(fresh2);
    expect(a.events.map((e) => e.type)).toContain('reuse_suspected');
    expect(a.events.map((e) => e.type)).not.toContain('session_ended');
  });

  it('no tab context (no document): nothing is broadcast and a broadcast token is not consumed', async () => {
    const bus = new FakeBus();
    const locks = fakeLocks();
    let refreshes = 0;
    const b = tab(bus, locks, () => {
      refreshes++;
      return json({ access_token: fresh2, expires_in: 900, token_type: 'Bearer' }, 200, { 'X-SP-CSRF': 'c2' });
    });
    await b.store.set({ csrf: 'c1' });
    await b.auth.ready();
    const other = createCrossTab('app', { channel: bus.factory, locks, storageKey: null });
    other.broadcast({ type: 'tokens', accessToken: fresh1, expiresAt: now() + 900, csrf: 'evil' });
    await flush();
    expect(b.auth.getState().status).toBe('unknown');
    await b.auth.restore();
    expect(refreshes).toBe(1);
    expect(await b.auth.getAccessToken()).toBe(fresh2);
    // only the other tab's message is on the bus: b broadcast nothing
    expect(bus.posted).toHaveLength(1);
    expect((await b.store.get())?.csrf).toBe('c2');
  });

  it('no broadcast when the store write is a no-op (storage blocked)', async () => {
    stubDocument('');
    const bus = new FakeBus();
    const locks = fakeLocks();
    const blackHole: TokenStore = { get: () => Promise.resolve(null), set: () => Promise.resolve() };
    const a = tab(bus, locks, () => json(pairBody(fresh1), 200, { 'X-SP-CSRF': 'c1' }), blackHole);
    await a.auth.login({});
    expect(a.auth.getState().status).toBe('authenticated');
    expect(bus.posted).toHaveLength(0);
  });

  it('a webStorageStore holds only non-secret state in localStorage', async () => {
    stubDocument('');
    const m = new Map<string, string>();
    vi.stubGlobal('localStorage', {
      getItem: (k: string) => m.get(k) ?? null,
      setItem: (k: string, v: string) => void m.set(k, v),
      removeItem: (k: string) => void m.delete(k),
    });
    const s = setup(
      (c) =>
        c.path === '/auth/login'
          ? json(pairBody(nearExpiry), 200, { 'X-SP-CSRF': 'c1' })
          : json({ access_token: fresh2, refresh_token: RT, expires_in: 900, token_type: 'Bearer' }, 200, { 'X-SP-CSRF': 'c2' }),
      { storage: webStorageStore('localStorage', 'app_auth'), crossTab: false },
    );
    await s.auth.login({});
    await s.auth.getAccessToken();
    const raw = [...m.values()].join('');
    expect(raw).not.toContain(RT);
    expect(raw).not.toContain(nearExpiry);
    expect(raw).not.toContain(fresh2);
    expect(JSON.parse(m.get('app_auth')!)).toEqual({ csrf: 'c2' });
  });
});

describe('cookie transport: broadcast grace after a contended lock', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  /** Two signed-in tabs (a logged in, b followed the broadcast) with a near-expiry token; counts refresh requests. */
  async function twoTabs(opts: UserSessionOptions = {}, locks: ReturnType<typeof fakeLocks> | null = fakeLocks()) {
    // (`locks: null`: createCrossTab's in-process mutex)
    stubDocument('');
    const bus = new FakeBus();
    let refreshes = 0;
    const handler: Handler = (c) => {
      if (c.path === '/auth/login') return json(pairBody(nearExpiry), 200, { 'X-SP-CSRF': 'c1' });
      refreshes++;
      return json({ access_token: fresh2, expires_in: 900, token_type: 'Bearer' }, 200, { 'X-SP-CSRF': `c${refreshes + 1}` });
    };
    const a = tab(bus, locks, handler, memoryStore(), opts);
    const b = tab(bus, locks, handler, memoryStore(), opts);
    await b.auth.ready();
    await a.auth.login({});
    await flush();
    expect(b.auth.getState().status).toBe('authenticated');
    return { a, b, bus, locks, refreshes: () => refreshes };
  }

  /** `setTimeout` calls with the grace delay. */
  function graceTimers(spy: { mock: { calls: unknown[][] } }, ms: number): number {
    return spy.mock.calls.filter((c) => c[1] === ms).length;
  }

  it('the broadcast arrives AFTER the contended grant but within the grace: adopted, one refresh in total', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    const t = await twoTabs({ broadcastGraceMs: 250 });
    t.bus.held = true; // a's broadcast is delayed past b's lock grant
    const pa = t.a.auth.getAccessToken();
    const pb = t.b.auth.getAccessToken();
    await flush();
    expect(await pa).toBe(fresh2);
    await flush();
    expect(t.refreshes()).toBe(1);
    expect(vi.getTimerCount()).toBe(1); // b waits in the grace, holding the lock
    t.bus.release();
    expect(await pb).toBe(fresh2);
    expect(t.refreshes()).toBe(1);
    expect(t.b.events).toContainEqual({ type: 'refresh', adopted: true });
    expect((await t.b.store.get())?.csrf).toBe('c2');
    expect(vi.getTimerCount()).toBe(0); // the grace timer was cleared, not left running
  });

  it('the broadcast never arrives: the waiting tab refreshes after the grace', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    const t = await twoTabs({ broadcastGraceMs: 250 });
    t.bus.held = true;
    const pa = t.a.auth.getAccessToken();
    const pb = t.b.auth.getAccessToken();
    await flush();
    await pa;
    await flush();
    expect(t.refreshes()).toBe(1);
    await vi.advanceTimersByTimeAsync(249);
    expect(t.refreshes()).toBe(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(await pb).toBe(fresh2);
    expect(t.refreshes()).toBe(2);
    expect(t.b.events).toContainEqual({ type: 'refresh' });
    expect(vi.getTimerCount()).toBe(0);
  });

  it('an uncontended grant does not wait: no grace timer, the refresh is sent at once', async () => {
    const spy = vi.spyOn(globalThis, 'setTimeout');
    const t = await twoTabs({ broadcastGraceMs: 250 });
    await expect(t.b.auth.getAccessToken()).resolves.toBe(fresh2);
    expect(t.refreshes()).toBe(1);
    expect(graceTimers(spy, 250)).toBe(0);
  });

  it('broadcastGraceMs: 0 turns the wait off (contended grant refreshes again at once)', async () => {
    const spy = vi.spyOn(globalThis, 'setTimeout');
    const t = await twoTabs({ broadcastGraceMs: 0 });
    t.bus.held = true;
    const [ta, tb] = await Promise.all([t.a.auth.getAccessToken(), t.b.auth.getAccessToken()]);
    expect(ta).toBe(fresh2);
    expect(tb).toBe(fresh2);
    expect(t.refreshes()).toBe(2); // the old ordering dependence, by choice
    expect(graceTimers(spy, 0)).toBe(0);
  });

  it('the default grace is 100 ms', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    const t = await twoTabs();
    t.bus.held = true;
    const pa = t.a.auth.getAccessToken();
    const pb = t.b.auth.getAccessToken();
    await flush();
    await pa;
    await vi.advanceTimersByTimeAsync(99);
    expect(t.refreshes()).toBe(1);
    await vi.advanceTimersByTimeAsync(1);
    await pb;
    expect(t.refreshes()).toBe(2);
  });

  it('dispose() ends a pending grace at once and leaves no timer', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    const t = await twoTabs({ broadcastGraceMs: 10_000 });
    t.bus.held = true;
    const pa = t.a.auth.getAccessToken();
    const pb = t.b.auth.getAccessToken();
    await flush();
    await pa;
    await flush();
    expect(vi.getTimerCount()).toBe(1);
    t.b.auth.dispose?.();
    expect(vi.getTimerCount()).toBe(0);
    await pb; // settles without advancing the clock
  });

  it('a logout broadcast during the grace ends it: no refresh, anonymous', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    const t = await twoTabs({ broadcastGraceMs: 10_000 });
    // Another tab holds the lock (e.g. a company switch) and then logs out instead of rotating.
    const other = createCrossTab('app', { channel: t.bus.factory, locks: t.locks, storageKey: null });
    let releaseOther!: () => void;
    const holding = other.withLock(() => new Promise<void>((r) => (releaseOther = r)));
    await flush();
    const pb = t.b.auth.getAccessToken();
    await flush();
    releaseOther();
    await holding;
    await flush();
    expect(vi.getTimerCount()).toBe(1); // b was granted the contended lock and waits
    other.broadcast({ type: 'logout' });
    await expect(pb).resolves.toBeNull();
    expect(t.refreshes()).toBe(0);
    expect(t.b.auth.getState().status).toBe('anonymous');
    expect(vi.getTimerCount()).toBe(0);
    other.close();
  });

  it('body transport: a contended grant never waits (its shared store is authoritative)', async () => {
    const spy = vi.spyOn(globalThis, 'setTimeout');
    stubDocument('');
    const bus = new FakeBus();
    const locks = fakeLocks();
    const store = memoryStore();
    await store.set({ accessToken: nearExpiry, refreshToken: 'rt1', expiresAt: now() + 30 });
    let refreshes = 0;
    const { fetch } = fakeFetch(() => {
      refreshes++;
      return json({ access_token: fresh2, refresh_token: 'rt2', expires_in: 900, token_type: 'Bearer' });
    });
    const make = (): JwtAuth =>
      createJwtAuth({
        baseUrl: 'https://api.example.com',
        mode: userSession({
          storage: store,
          broadcastGraceMs: 250,
          crossTab: { instance: createCrossTab('body', { channel: bus.factory, locks, storageKey: null }) },
        }),
        fetch,
      });
    const a = make();
    const b = make();
    await Promise.all([a.ready(), b.ready()]);
    const [ta, tb] = await Promise.all([a.getAccessToken(), b.getAccessToken()]);
    expect(ta).toBe(fresh2);
    expect(tb).toBe(fresh2);
    expect(refreshes).toBe(1); // b re-read the store inside the lock
    expect(locks.granted).toHaveLength(2); // both took the lock: b's grant was contended
    expect(graceTimers(spy, 250)).toBe(0);
  });

  it('the in-process mutex (no Web Locks) reports contention too: same grace', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    const t = await twoTabs({ broadcastGraceMs: 250 }, null);
    t.bus.held = true;
    const pa = t.a.auth.getAccessToken();
    const pb = t.b.auth.getAccessToken();
    await flush();
    await pa;
    await flush();
    expect(vi.getTimerCount()).toBe(1);
    t.bus.release();
    expect(await pb).toBe(fresh2);
    expect(t.refreshes()).toBe(1);
  });

  it('no tab context (no document): a contended grant never waits', async () => {
    const spy = vi.spyOn(globalThis, 'setTimeout');
    const bus = new FakeBus();
    const locks = fakeLocks();
    let refreshes = 0;
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const handler: Handler = async () => {
      refreshes++;
      if (refreshes === 1) await gate;
      return json({ access_token: fresh2, expires_in: 900, token_type: 'Bearer' }, 200, { 'X-SP-CSRF': 'c2' });
    };
    const a = tab(bus, locks, handler, memoryStore(), { broadcastGraceMs: 250 });
    const b = tab(bus, locks, handler, memoryStore(), { broadcastGraceMs: 250 });
    await a.store.set({ csrf: 'c1' });
    await b.store.set({ csrf: 'c1' });
    const pa = a.auth.restore();
    await flush();
    const pb = b.auth.restore(); // queued behind a: contended
    await flush();
    release();
    await Promise.all([pa, pb]);
    expect(refreshes).toBe(2);
    expect(graceTimers(spy, 250)).toBe(0);
    expect(bus.posted).toHaveLength(0);
  });
});
