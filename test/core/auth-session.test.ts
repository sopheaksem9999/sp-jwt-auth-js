import { describe, expect, it, vi } from 'vitest';
import { createJwtAuth, userSession } from '../../src/core/create-jwt-auth';
import type { AuthEvent, JwtAuthOptions } from '../../src/core/create-jwt-auth';
import { memoryStore } from '../../src/core/stores';
import type { TokenStore } from '../../src/core/stores';
import { SpAuthError } from '../../src/core/errors';

function b64url(s: string): string {
  const bytes = new TextEncoder().encode(s);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function jwt(payload: Record<string, unknown>): string {
  return `${b64url(JSON.stringify({ alg: 'none', typ: 'JWT' }))}.${b64url(JSON.stringify(payload))}.sig`;
}

const now = (): number => Math.floor(Date.now() / 1000);

interface Call {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: unknown;
  credentials?: string;
}

type Responder = (call: Call) => Response | Promise<Response>;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

function fakeFetch(responder: Responder): { fetch: typeof fetch; calls: Call[] } {
  const calls: Call[] = [];
  const f = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const headers: Record<string, string> = {};
    new Headers(init?.headers).forEach((v, k) => {
      headers[k] = v;
    });
    const raw = init?.body;
    const call: Call = {
      url: String(input),
      method: init?.method ?? 'GET',
      headers,
      body: typeof raw === 'string' ? JSON.parse(raw) : raw,
      credentials: init?.credentials,
    };
    calls.push(call);
    return responder(call);
  };
  return { fetch: f as typeof fetch, calls };
}

const access = jwt({ sub: '7', exp: now() + 900, company_id: 42, impersonated: true, scopes: ['a'] });
const pair = { access_token: access, refresh_token: 'r1', expires_in: 900, token_type: 'Bearer' };

function setup(
  responder: Responder,
  extra: Partial<JwtAuthOptions> = {},
  store: TokenStore = memoryStore(),
): { auth: ReturnType<typeof createJwtAuth>; calls: Call[]; store: TokenStore; events: AuthEvent[] } {
  const { fetch, calls } = fakeFetch(responder);
  const events: AuthEvent[] = [];
  const auth = createJwtAuth({
    baseUrl: 'https://api.test/api/',
    endpoints: { login: '/auth/login', secondFactor: '/auth/login/2fa' },
    mode: userSession({ storage: store }),
    fetch,
    onEvent: (e) => events.push(e),
    ...extra,
  });
  return { auth, calls, store, events };
}

describe('login', () => {
  it('posts to endpoints.login and stores the pair from { token: {...} }', async () => {
    const { auth, calls, store, events } = setup(() => json({ user: { id: 7 }, token: pair }));
    const res = await auth.login({ email: 'a@b.c', password: 'p' });
    expect(res).toEqual({ status: 'authenticated' });
    expect(calls[0]?.url).toBe('https://api.test/api/auth/login');
    expect(calls[0]?.method).toBe('POST');
    expect(calls[0]?.body).toEqual({ email: 'a@b.c', password: 'p' });
    expect(calls[0]?.headers['content-type']).toBe('application/json');
    const t = await store.get();
    expect(t?.accessToken).toBe(access);
    expect(t?.refreshToken).toBe('r1');
    expect(t?.expiresAt).toBeGreaterThanOrEqual(now() + 899);
    expect(auth.getState().status).toBe('authenticated');
    expect(events.map((e) => e.type)).toContain('login');
  });

  it('stores the pair from a SaaS envelope and reads companyId / impersonated from claims', async () => {
    const { auth, store } = setup(() => json({ success: true, error_code: 0, data: { ...pair, company_id: 42 }, meta: {} }), {
      unwrap: 'sp-laravel-api',
    });
    await auth.login({ email: 'x', password: 'y' });
    expect((await store.get())?.accessToken).toBe(access);
    const s = auth.getState();
    expect(s.status).toBe('authenticated');
    expect(s.companyId).toBe('42');
    expect(s.impersonated).toBe(true);
    expect(s.user).toBeNull();
    expect(s.claims?.sub).toBe('7');
  });

  it('reads companyId from a custom companyClaim', async () => {
    const tok = jwt({ sub: '1', exp: now() + 900, tenant_id: 'acme' });
    const { auth } = setup(() => json({ ...pair, access_token: tok }), { companyClaim: 'tenant_id' });
    await auth.login({});
    expect(auth.getState().companyId).toBe('acme');
    expect(auth.getState().impersonated).toBe(false);
  });

  it('returns second_factor_required for a raw requires_2fa body without unwrapping, storing nothing', async () => {
    const { auth, store } = setup(() => json({ requires_2fa: true, '2fa_token': 't' }), { unwrap: 'sp-laravel-api' });
    const res = await auth.login({ email: 'x' });
    expect(res).toEqual({ status: 'second_factor_required', challenge: { kind: '2fa_token', token: 't' } });
    expect(await store.get()).toBeNull();
    expect(auth.getState().status).toBe('anonymous');
  });

  it('sends X-Device-Id / X-Device-Name when device is configured', async () => {
    const { auth, calls } = setup(() => json(pair), { device: { id: 'dev-1', name: 'Chrome' } });
    await auth.login({});
    expect(calls[0]?.headers['x-device-id']).toBe('dev-1');
    expect(calls[0]?.headers['x-device-name']).toBe('Chrome');
  });

  it('generates a stable device id from the store when device.id is not given', async () => {
    const { auth, calls, store } = setup(() => json(pair), { device: { name: 'CLI' } });
    await auth.login({});
    await auth.login({});
    const id = calls[0]?.headers['x-device-id'];
    expect(id).toMatch(/[0-9a-f-]{36}/);
    expect(calls[1]?.headers['x-device-id']).toBe(id);
    expect((await store.get())?.deviceId).toBe(id);
  });

  it('sends no device headers without the device option', async () => {
    const { auth, calls } = setup(() => json(pair));
    await auth.login({});
    expect(calls[0]?.headers['x-device-id']).toBeUndefined();
  });

  it('throws an SpAuthError from a non-2xx login', async () => {
    const { auth } = setup(() => json({ message: 'Invalid credentials' }, 401));
    const err = await auth.login({}).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(SpAuthError);
    expect((err as SpAuthError).status).toBe(401);
    expect((err as SpAuthError).module).toBe('login');
  });

  it('throws when the body has no token pair', async () => {
    const { auth } = setup(() => json({ ok: true }));
    await expect(auth.login({})).rejects.toBeInstanceOf(SpAuthError);
  });
});

describe('verifySecondFactor', () => {
  it('posts the default 2fa_token body and stores the pair', async () => {
    const { auth, calls, store } = setup(() => json(pair));
    await auth.verifySecondFactor({ kind: '2fa_token', token: 't' }, '123456');
    expect(calls[0]?.url).toBe('https://api.test/api/auth/login/2fa');
    expect(calls[0]?.body).toEqual({ '2fa_token': 't', otp: '123456' });
    expect((await store.get())?.accessToken).toBe(access);
    expect(auth.getState().status).toBe('authenticated');
  });

  it('posts { challenge_id, code } for challenge_id', async () => {
    const { auth, calls } = setup(() => json(pair));
    await auth.verifySecondFactor({ kind: 'challenge_id', token: 'c1' }, '9');
    expect(calls[0]?.body).toEqual({ challenge_id: 'c1', code: '9' });
  });

  it('uses secondFactorBody when given', async () => {
    const { auth, calls } = setup(() => json(pair), { secondFactorBody: (c, code) => ({ t: c.token, c: code }) });
    await auth.verifySecondFactor({ kind: '2fa_token', token: 't' }, '1');
    expect(calls[0]?.body).toEqual({ t: 't', c: '1' });
  });
});

describe('headers and tokens', () => {
  it('getHeaders returns a bearer header when logged in and {} when anonymous', async () => {
    const { auth } = setup(() => json(pair));
    expect(await auth.getHeaders()).toEqual({});
    expect(await auth.getAccessToken()).toBeNull();
    await auth.login({});
    expect(await auth.getHeaders()).toEqual({ Authorization: `Bearer ${access}` });
    expect(await auth.getAccessToken()).toBe(access);
  });

  it('acceptTokens stores a pair from a raw body', async () => {
    const { auth, store } = setup(() => json({}));
    await auth.acceptTokens({ token: pair });
    expect((await store.get())?.refreshToken).toBe('r1');
    expect(auth.getState().status).toBe('authenticated');
  });

  it('decodeClaims decodes a given token or the current one', async () => {
    const { auth } = setup(() => json(pair));
    expect(auth.decodeClaims()).toBeNull();
    await auth.login({});
    expect(auth.decodeClaims()?.sub).toBe('7');
    expect(auth.decodeClaims(jwt({ sub: 9 }))?.sub).toBe('9');
  });
});

describe('logout', () => {
  async function loggedIn(responder: Responder, extra: Partial<JwtAuthOptions> = {}) {
    let first = true;
    const r = setup((c) => {
      if (first) {
        first = false;
        return json(pair);
      }
      return responder(c);
    }, extra);
    await r.auth.login({});
    r.calls.length = 0;
    return r;
  }

  it('calls host endpoints.logout with the bearer token and forwards everywhere', async () => {
    const { auth, calls, store, events } = await loggedIn(() => json({}), {
      endpoints: { login: '/auth/login', logout: '/auth/logout' },
    });
    await auth.logout({ everywhere: true });
    expect(calls[0]?.url).toBe('https://api.test/api/auth/logout');
    expect(calls[0]?.headers.authorization).toBe(`Bearer ${access}`);
    expect(calls[0]?.body).toEqual({ everywhere: true });
    expect((await store.get())?.accessToken).toBeUndefined();
    expect(auth.getState().status).toBe('anonymous');
    expect(events.map((e) => e.type)).toContain('logout');
  });

  it('falls back to the package /auth/token/revoke route without everywhere in the body', async () => {
    const { auth, calls } = await loggedIn(() => new Response(null, { status: 204 }));
    await auth.logout({ everywhere: true });
    expect(calls[0]?.url).toBe('https://api.test/api/auth/token/revoke');
    expect(calls[0]?.method).toBe('POST');
    expect(calls[0]?.headers.authorization).toBe(`Bearer ${access}`);
    expect(calls[0]?.body).toBeUndefined();
  });

  it('clears storage even when the call rejects', async () => {
    const { auth, store } = await loggedIn(() => Promise.reject(new TypeError('offline')));
    await auth.logout();
    expect((await store.get())?.accessToken).toBeUndefined();
    expect(auth.getState().status).toBe('anonymous');
  });

  it('treats 401 as already logged out', async () => {
    const { auth, store } = await loggedIn(() => json({ message: 'Unauthenticated.' }, 401));
    await expect(auth.logout()).resolves.toBeUndefined();
    expect(await store.get()).toBeNull();
    expect(auth.getState().status).toBe('anonymous');
  });

  it('keeps the deviceId', async () => {
    const { auth, store } = await loggedIn(() => json({}), { device: { name: 'x' } });
    const id = (await store.get())?.deviceId;
    expect(id).toBeTruthy();
    await auth.logout();
    expect(await store.get()).toEqual({ deviceId: id });
  });

  it('clearSession clears without a network call', async () => {
    const { auth, calls, store } = await loggedIn(() => json({}));
    await auth.clearSession();
    expect(calls).toHaveLength(0);
    expect(await store.get()).toBeNull();
    expect(auth.getState().status).toBe('anonymous');
  });
});

describe('state', () => {
  it('subscribe fires on change, unsubscribe works, getState is referentially stable', async () => {
    const { auth } = setup(() => json(pair));
    await auth.ready();
    const a = auth.getState();
    expect(auth.getState()).toBe(a);
    const l = vi.fn();
    const unsub = auth.subscribe(l);
    await auth.login({});
    expect(l).toHaveBeenCalled();
    const b = auth.getState();
    expect(b).not.toBe(a);
    expect(auth.getState()).toBe(b);
    unsub();
    l.mockClear();
    await auth.clearSession();
    expect(l).not.toHaveBeenCalled();
  });

  it('a throwing listener or onEvent does not break others', async () => {
    const { fetch } = fakeFetch(() => json(pair));
    const auth = createJwtAuth({
      baseUrl: 'https://api.test',
      endpoints: { login: '/login' },
      mode: userSession({ storage: memoryStore() }),
      fetch,
      onEvent: () => {
        throw new Error('boom');
      },
    });
    const good = vi.fn();
    auth.subscribe(() => {
      throw new Error('bad listener');
    });
    auth.subscribe(good);
    await expect(auth.login({})).resolves.toEqual({ status: 'authenticated' });
    expect(good).toHaveBeenCalled();
  });

  it('starts unknown and hydrates from a pre-filled store on ready()', async () => {
    const store = memoryStore();
    await store.set({ accessToken: access, refreshToken: 'r', expiresAt: now() + 900 });
    const { auth } = setup(() => json({}), {}, store);
    expect(auth.getState().status).toBe('unknown');
    await auth.ready();
    expect(auth.getState().status).toBe('authenticated');
    expect(auth.getState().companyId).toBe('42');
  });

  it('hydrates an empty store as anonymous', async () => {
    const { auth } = setup(() => json({}));
    await auth.ready();
    expect(auth.getState().status).toBe('anonymous');
  });

  it('an expired stored token with a refresh token hydrates as authenticated', async () => {
    const store = memoryStore();
    await store.set({ accessToken: access, refreshToken: 'r', expiresAt: now() - 10 });
    const { auth } = setup(() => json({}), {}, store);
    await auth.ready();
    expect(auth.getState().status).toBe('authenticated');
  });

  it('an expired stored token without a refresh token hydrates as anonymous and is cleared (deviceId kept)', async () => {
    const store = memoryStore();
    await store.set({ accessToken: access, expiresAt: now() - 10, deviceId: 'd1' });
    const { auth } = setup(() => json({}), {}, store);
    await auth.ready();
    expect(auth.getState().status).toBe('anonymous');
    expect(await store.get()).toEqual({ deviceId: 'd1' });
    expect(await auth.getAccessToken()).toBeNull();
  });
});

describe('endpoint', () => {
  it('throws not_configured with the module for an unset optional endpoint', () => {
    const { auth } = setup(() => json({}));
    let err: unknown;
    try {
      auth.endpoint('whoami', 'x');
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(SpAuthError);
    expect((err as SpAuthError).code).toBe('not_configured');
    expect((err as SpAuthError).module).toBe('x');
  });

  it('returns package defaults', () => {
    const { auth } = setup(() => json({}));
    expect(auth.endpoint('refresh', 'x')).toBe('/auth/token/refresh');
    expect(auth.endpoint('otp', 'x')).toBe('/otp');
    expect(auth.endpoint('jwks', 'x')).toBe('/.well-known/sp-jwt-auth/jwks.json');
    expect(auth.endpoint('login', 'x')).toBe('/auth/login');
  });
});

describe('http', () => {
  it('accepts a full URL, sends credentials and tolerates 202/204', async () => {
    const { auth, calls } = setup((c) => (c.url.endsWith('/a') ? new Response(null, { status: 204 }) : json({ n: 1 }, 202)));
    const r1 = await auth.http<null>({ method: 'POST', endpoint: 'https://other.test/a', credentials: 'include' });
    expect(r1.body).toBeNull();
    expect(calls[0]?.url).toBe('https://other.test/a');
    expect(calls[0]?.credentials).toBe('include');
    const r2 = await auth.http<{ n: number }>({ method: 'GET', endpoint: 'b' });
    expect(r2.body).toEqual({ n: 1 });
    expect(r2.response.status).toBe(202);
    expect(calls[1]?.url).toBe('https://api.test/api/b');
  });

  it('rethrows the caller abort reason', async () => {
    const hang: typeof fetch = (_i, init) =>
      new Promise((_r, reject) => {
        init?.signal?.addEventListener('abort', () => reject(init.signal?.reason));
      });
    const auth = createJwtAuth({ baseUrl: 'https://api.test', endpoints: {}, mode: userSession({ storage: memoryStore() }), fetch: hang });
    const ac = new AbortController();
    const reason = new Error('user cancelled');
    const p = auth.http({ method: 'GET', endpoint: '/x', signal: ac.signal });
    ac.abort(reason);
    await expect(p).rejects.toBe(reason);
  });

  it('throws SpAuthError timeout after timeoutMs', async () => {
    const hang: typeof fetch = (_i, init) =>
      new Promise((_r, reject) => {
        init?.signal?.addEventListener('abort', () => reject(new Error('aborted')));
      });
    const auth = createJwtAuth({
      baseUrl: 'https://api.test',
      endpoints: {},
      mode: userSession({ storage: memoryStore() }),
      fetch: hang,
      timeoutMs: 10,
    });
    const err = await auth.http({ method: 'GET', endpoint: '/x' }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(SpAuthError);
    expect((err as SpAuthError).code).toBe('timeout');
  });

  it('wraps a fetch rejection as SpAuthError network', async () => {
    const { auth } = setup(() => Promise.reject(new TypeError('Failed to fetch')));
    const err = await auth.http({ method: 'GET', endpoint: '/x', module: 'm' }).catch((e: unknown) => e);
    expect((err as SpAuthError).code).toBe('network');
    expect((err as SpAuthError).module).toBe('m');
  });
});

describe('userSession', () => {
  it("throws not_configured for transport 'cookie' (not implemented yet)", () => {
    let err: unknown;
    try {
      userSession({ storage: memoryStore(), transport: 'cookie' });
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(SpAuthError);
    expect((err as SpAuthError).code).toBe('not_configured');
  });
});
