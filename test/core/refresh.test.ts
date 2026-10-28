import { describe, expect, it } from 'vitest';
import { createJwtAuth, userSession } from '../../src/core/create-jwt-auth';
import type { AuthEvent, JwtAuthOptions } from '../../src/core/create-jwt-auth';
import { SpAuthError } from '../../src/core/errors';
import { createRefresher, waitFor } from '../../src/core/refresh';
import { memoryStore } from '../../src/core/stores';
import type { TokenStore, Tokens } from '../../src/core/stores';

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
  signal?: AbortSignal | null;
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
      signal: init?.signal,
    };
    calls.push(call);
    return responder(call);
  };
  return { fetch: f as typeof fetch, calls };
}

interface Deferred<T> {
  promise: Promise<T>;
  resolve(v: T): void;
}

function deferred<T>(): Deferred<T> {
  let resolve!: (v: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

const access1 = jwt({ sub: '7', exp: now() + 30, company_id: 42 });
const access2 = jwt({ sub: '7', exp: now() + 900, company_id: 42 });
const pair2 = { access_token: access2, refresh_token: 'r2', expires_in: 900, token_type: 'Bearer' };

async function seeded(
  tokens: Tokens | null,
  responder: Responder,
  extra: Partial<JwtAuthOptions> = {},
): Promise<{ auth: ReturnType<typeof createJwtAuth>; calls: Call[]; store: TokenStore; events: AuthEvent[] }> {
  const store = memoryStore();
  await store.set(tokens);
  const { fetch, calls } = fakeFetch(responder);
  const events: AuthEvent[] = [];
  const auth = createJwtAuth({
    baseUrl: 'https://api.test/api',
    endpoints: { login: '/auth/login' },
    mode: userSession({ storage: store }),
    fetch,
    onEvent: (e) => events.push(e),
    ...extra,
  });
  return { auth, calls, store, events };
}

/** Logged in with an access token 30 s from expiry (inside the default 60 s window). */
const nearExpiry = (): Tokens => ({ accessToken: access1, refreshToken: 'r1', expiresAt: now() + 30 });

function eventTypes(events: AuthEvent[]): string[] {
  return events.map((e) => e.type);
}

describe('createRefresher', () => {
  it('shares one in-flight promise between concurrent callers and clears it after a failure', async () => {
    let runs = 0;
    let fail = true;
    const gate = deferred<void>();
    const r = createRefresher({
      async perform() {
        runs++;
        await gate.promise;
        if (fail) throw new Error('boom');
      },
    });
    const a = r.refresh();
    const b = r.refresh();
    expect(a).toBe(b);
    gate.resolve();
    await expect(a).rejects.toThrow('boom');
    expect(runs).toBe(1);
    fail = false;
    await expect(r.refresh()).resolves.toBeUndefined();
    expect(runs).toBe(2);
  });

  it('does not stick when perform throws synchronously', async () => {
    let runs = 0;
    const r = createRefresher({
      perform() {
        runs++;
        if (runs === 1) throw new Error('sync');
        return Promise.resolve();
      },
    });
    await expect(r.refresh()).rejects.toThrow('sync');
    await expect(r.refresh()).resolves.toBeUndefined();
    expect(runs).toBe(2);
  });
});

describe('proactive refresh in getAccessToken', () => {
  it('100 concurrent getAccessToken() calls within the ahead window make exactly one refresh request', async () => {
    const gate = deferred<void>();
    const { auth, calls } = await seeded(nearExpiry(), async () => {
      await gate.promise;
      return json(pair2);
    });
    const all = Promise.all(Array.from({ length: 100 }, () => auth.getAccessToken()));
    await new Promise((r) => setTimeout(r, 0));
    gate.resolve();
    const tokens = await all;
    expect(calls).toHaveLength(1);
    expect(tokens.every((t) => t === access2)).toBe(true);
  });

  it('does not refresh when exp - now >= refreshAheadSeconds', async () => {
    const { auth, calls } = await seeded({ accessToken: access1, refreshToken: 'r1', expiresAt: now() + 61 }, () => json(pair2));
    expect(await auth.getAccessToken()).toBe(access1);
    expect(calls).toHaveLength(0);
  });

  it('honours a custom refreshAheadSeconds', async () => {
    const { auth, calls } = await seeded(
      { accessToken: access1, refreshToken: 'r1', expiresAt: now() + 100 },
      () => json(pair2),
      { refreshAheadSeconds: 120 },
    );
    expect(await auth.getAccessToken()).toBe(access2);
    expect(calls).toHaveLength(1);
  });

  it('refreshes when exp is already in the past (clock skew / offline)', async () => {
    const { auth, calls } = await seeded({ accessToken: access1, refreshToken: 'r1', expiresAt: now() - 3600 }, () => json(pair2));
    expect(await auth.getAccessToken()).toBe(access2);
    expect(calls).toHaveLength(1);
  });

  it('falls back to the expires_in expiry for an opaque access token', async () => {
    let n = 0;
    const { auth, calls, store } = await seeded(null, () =>
      json(n++ === 0 ? { access_token: 'opaque-1', refresh_token: 'r1', expires_in: 30, token_type: 'Bearer' } : pair2),
    );
    await auth.login({});
    const exp = (await store.get())?.expiresAt ?? 0;
    expect(exp).toBeGreaterThanOrEqual(now() + 29);
    expect(exp).toBeLessThanOrEqual(now() + 31);
    expect(await auth.getAccessToken()).toBe(access2);
    expect(calls).toHaveLength(2);
  });

  it('JWT exp wins over expires_in; exp 0 is not a real expiry', async () => {
    const withExp = jwt({ sub: '1', exp: now() + 900 });
    const zeroExp = jwt({ sub: '1', exp: 0 });
    const bodies = [
      { access_token: withExp, refresh_token: 'a', expires_in: 30, token_type: 'Bearer' },
      { access_token: zeroExp, refresh_token: 'b', expires_in: 600, token_type: 'Bearer' },
    ];
    let n = 0;
    const { auth, store } = await seeded(null, () => json(bodies[n++]));
    await auth.login({});
    expect((await store.get())?.expiresAt).toBe(decodeExp(withExp));
    await auth.login({});
    const e = (await store.get())?.expiresAt ?? 0;
    expect(e).toBeGreaterThanOrEqual(now() + 599);
    expect(e).toBeLessThanOrEqual(now() + 601);
  });

  it('returns null when logged out, without a request', async () => {
    const { auth, calls } = await seeded(null, () => json(pair2));
    expect(await auth.getAccessToken()).toBeNull();
    expect(calls).toHaveLength(0);
  });

  it('returns null and ends the session when the token expired and there is no refresh token', async () => {
    const { auth, calls, store, events } = await seeded({ accessToken: access1, expiresAt: now() + 30, deviceId: 'd1' }, () =>
      json(pair2),
    );
    await auth.ready();
    expect(await auth.getAccessToken()).toBe(access1); // not expired yet: still usable, nothing to refresh with
    await store.set({ accessToken: access1, expiresAt: now() - 1, deviceId: 'd1' });
    expect(await auth.getAccessToken()).toBeNull();
    expect(calls).toHaveLength(0);
    expect(await store.get()).toEqual({ deviceId: 'd1' });
    expect(auth.getState().status).toBe('anonymous');
    expect(eventTypes(events)).toContain('session_ended');
  });

  it('returns the still-valid token when a proactive refresh fails transiently', async () => {
    const { auth, store } = await seeded(nearExpiry(), () => Promise.reject(new TypeError('offline')));
    expect(await auth.getAccessToken()).toBe(access1);
    expect((await store.get())?.refreshToken).toBe('r1');
  });

  it('rejects with network when the token already expired and the refresh fails transiently', async () => {
    const { auth } = await seeded({ accessToken: access1, refreshToken: 'r1', expiresAt: now() - 5 }, () =>
      Promise.reject(new TypeError('offline')),
    );
    const err = await auth.getAccessToken().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(SpAuthError);
    expect((err as SpAuthError).code).toBe('network');
  });

  it('getHeaders uses the refreshed token', async () => {
    const { auth } = await seeded(nearExpiry(), () => json(pair2));
    expect(await auth.getHeaders()).toEqual({ Authorization: `Bearer ${access2}` });
  });
});

function decodeExp(t: string): number {
  const p = t.split('.')[1] ?? '';
  return (JSON.parse(atob(p.replace(/-/g, '+').replace(/_/g, '/'))) as { exp: number }).exp;
}

describe('refresh request and rotation', () => {
  it('POSTs { refresh_token } to the default route without a bearer header and stores both new tokens', async () => {
    const { auth, calls, store, events } = await seeded(
      { ...nearExpiry(), deviceId: 'd1', lastCompanyId: '42', csrf: 'c1' },
      () => json(pair2),
    );
    await auth.ready();
    const before = auth.getState();
    await auth.refresh();
    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe('https://api.test/api/auth/token/refresh');
    expect(calls[0]?.method).toBe('POST');
    expect(calls[0]?.body).toEqual({ refresh_token: 'r1' });
    expect(calls[0]?.headers.authorization).toBeUndefined();
    const t = await store.get();
    expect(t?.accessToken).toBe(access2);
    expect(t?.refreshToken).toBe('r2');
    expect(t?.deviceId).toBe('d1');
    expect(t?.lastCompanyId).toBe('42');
    expect(t?.csrf).toBe('c1');
    expect(t?.expiresAt).toBe(decodeExp(access2));
    expect(auth.getState().status).toBe('authenticated');
    expect(auth.getState()).not.toBe(before);
    expect(auth.getState().claims?.exp).toBe(decodeExp(access2));
    expect(eventTypes(events)).toContain('refresh');
  });

  it('uses endpoints.refresh and unwraps an envelope', async () => {
    const { auth, calls, store } = await seeded(nearExpiry(), () => json({ success: true, error_code: 0, data: pair2, meta: {} }), {
      endpoints: { refresh: '/auth/refresh' },
      unwrap: 'sp-laravel-api',
    });
    await auth.refresh();
    expect(calls[0]?.url).toBe('https://api.test/api/auth/refresh');
    expect((await store.get())?.refreshToken).toBe('r2');
  });

  it('sends device headers on refresh', async () => {
    const { auth, calls } = await seeded(nearExpiry(), () => json(pair2), { device: { id: 'dev-1', name: 'Chrome' } });
    await auth.refresh();
    expect(calls[0]?.headers['x-device-id']).toBe('dev-1');
    expect(calls[0]?.headers['x-device-name']).toBe('Chrome');
  });

  it('a second refresh presents the rotated refresh token', async () => {
    let n = 0;
    const { auth, calls } = await seeded(nearExpiry(), () =>
      json(n++ === 0 ? pair2 : { ...pair2, refresh_token: 'r3' }),
    );
    await auth.refresh();
    await auth.refresh();
    expect(calls.map((c) => c.body)).toEqual([{ refresh_token: 'r1' }, { refresh_token: 'r2' }]);
  });

  it('an invalid pair in the response rejects with unknown and keeps the tokens', async () => {
    const { auth, store, events } = await seeded(nearExpiry(), () => json({ refresh_token: 'leak', expires_in: 'soon' }));
    await auth.ready();
    const before = auth.getState();
    const err = await auth.refresh().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(SpAuthError);
    expect((err as SpAuthError).code).toBe('unknown');
    expect(JSON.stringify((err as SpAuthError).body)).not.toContain('leak');
    expect((await store.get())?.refreshToken).toBe('r1');
    expect(auth.getState()).toBe(before);
    expect(eventTypes(events)).toContain('refresh_failed');
  });

  it('a refresh that resolves after logout does not restore the session', async () => {
    const gate = deferred<void>();
    const { auth, store } = await seeded({ ...nearExpiry(), deviceId: 'd1' }, async (c) => {
      if (c.url.endsWith('/auth/token/refresh')) {
        await gate.promise;
        return json(pair2);
      }
      return new Response(null, { status: 204 });
    });
    await auth.ready();
    const p = auth.refresh().catch((e: unknown) => e);
    await auth.logout();
    gate.resolve();
    await p;
    expect(await store.get()).toEqual({ deviceId: 'd1' });
    expect(auth.getState().status).toBe('anonymous');
  });
});

describe('refresh failure', () => {
  it('refresh 401 ends the session: store cleared (deviceId kept), anonymous, session_ended, handleUnauthorized false', async () => {
    const { auth, store, events } = await seeded({ ...nearExpiry(), deviceId: 'd1' }, () =>
      json({ message: 'Refresh token reused' }, 401),
    );
    await auth.ready();
    expect(await auth.handleUnauthorized()).toBe(false);
    expect(await store.get()).toEqual({ deviceId: 'd1' });
    expect(auth.getState().status).toBe('anonymous');
    expect(eventTypes(events)).toEqual(expect.arrayContaining(['refresh_failed', 'session_ended']));
    expect(await auth.getAccessToken()).toBeNull();
  });

  it('JwtAuth.refresh() rejects with session_ended on a refresh 401', async () => {
    const { auth } = await seeded(nearExpiry(), () => json({}, 401));
    const err = await auth.refresh().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(SpAuthError);
    expect((err as SpAuthError).code).toBe('session_ended');
    expect((err as SpAuthError).status).toBe(401);
  });

  it('getAccessToken returns null after a refresh 401', async () => {
    const { auth } = await seeded(nearExpiry(), () => json({}, 401));
    expect(await auth.getAccessToken()).toBeNull();
    expect(auth.getState().status).toBe('anonymous');
  });

  it('refresh 503 keeps the tokens and state; handleUnauthorized rejects with the 503 error', async () => {
    const { auth, store, events } = await seeded(nearExpiry(), () => json({ message: 'down' }, 503));
    await auth.ready();
    const before = auth.getState();
    const err = await auth.handleUnauthorized().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(SpAuthError);
    expect((err as SpAuthError).status).toBe(503);
    expect((await store.get())?.refreshToken).toBe('r1');
    expect((await store.get())?.accessToken).toBe(access1);
    expect(auth.getState()).toBe(before);
    expect(eventTypes(events)).toContain('refresh_failed');
    expect(eventTypes(events)).not.toContain('session_ended');
  });

  it('a network error keeps the tokens and state; handleUnauthorized rejects with network (status 0)', async () => {
    const { auth, store } = await seeded(nearExpiry(), () => Promise.reject(new TypeError('Failed to fetch')));
    await auth.ready();
    const before = auth.getState();
    const err = await auth.handleUnauthorized().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(SpAuthError);
    expect((err as SpAuthError).code).toBe('network');
    expect((err as SpAuthError).status).toBe(0);
    expect((await store.get())?.refreshToken).toBe('r1');
    expect(auth.getState()).toBe(before);
  });

  it('another 4xx rejects with that error and keeps the tokens', async () => {
    const { auth, store } = await seeded(nearExpiry(), () => json({ message: 'bad' }, 400));
    const err = await auth.handleUnauthorized().catch((e: unknown) => e);
    expect((err as SpAuthError).status).toBe(400);
    expect((await store.get())?.refreshToken).toBe('r1');
    expect(auth.getState().status).toBe('authenticated');
  });

  it('a failed refresh does not stick: a later call refreshes again', async () => {
    let n = 0;
    const { auth, calls } = await seeded(nearExpiry(), () =>
      n++ === 0 ? Promise.reject(new TypeError('offline')) : json(pair2),
    );
    await expect(auth.refresh()).rejects.toBeInstanceOf(SpAuthError);
    await auth.refresh();
    expect(calls).toHaveLength(2);
    expect(await auth.getAccessToken()).toBe(access2);
  });
});

describe('handleUnauthorized', () => {
  it('resolves true after a successful refresh', async () => {
    const { auth, store } = await seeded({ accessToken: access1, refreshToken: 'r1', expiresAt: now() + 900 }, () => json(pair2));
    expect(await auth.handleUnauthorized()).toBe(true);
    expect((await store.get())?.accessToken).toBe(access2);
  });

  it('concurrent calls share one refresh', async () => {
    const gate = deferred<void>();
    const { auth, calls } = await seeded(nearExpiry(), async () => {
      await gate.promise;
      return json(pair2);
    });
    const all = Promise.all([auth.handleUnauthorized(), auth.handleUnauthorized(), auth.handleUnauthorized()]);
    await new Promise((r) => setTimeout(r, 0));
    gate.resolve();
    expect(await all).toEqual([true, true, true]);
    expect(calls).toHaveLength(1);
  });

  it('resolves false without a request when there is no session', async () => {
    const { auth, calls, events } = await seeded(null, () => json(pair2));
    expect(await auth.handleUnauthorized()).toBe(false);
    expect(calls).toHaveLength(0);
    expect(eventTypes(events)).not.toContain('session_ended');
  });

  it('ends the session when there is an access token but no refresh token', async () => {
    const { auth, calls, events, store } = await seeded({ accessToken: access2, expiresAt: now() + 900, deviceId: 'd' }, () =>
      json(pair2),
    );
    expect(await auth.handleUnauthorized()).toBe(false);
    expect(calls).toHaveLength(0);
    expect(await store.get()).toEqual({ deviceId: 'd' });
    expect(auth.getState().status).toBe('anonymous');
    expect(eventTypes(events)).toContain('session_ended');
  });
});

describe('handleUnauthorized with the failed request', () => {
  it('a 401 that arrives after the refresh completed retries with the new token without refreshing again', async () => {
    const { auth, calls } = await seeded(nearExpiry(), () => json(pair2));
    expect(await auth.getAccessToken()).toBe(access2);
    expect(calls).toHaveLength(1);
    expect(await auth.handleUnauthorized({ headers: { Authorization: `Bearer ${access1}` } })).toBe(true);
    expect(await auth.handleUnauthorized({ headers: { authorization: `bearer ${access1}` } })).toBe(true);
    expect(calls).toHaveLength(1);
    expect(await auth.getAccessToken()).toBe(access2);
  });

  it('refreshes when the failed request carried the current token', async () => {
    let n = 0;
    const { auth, calls } = await seeded({ accessToken: access1, refreshToken: 'r1', expiresAt: now() + 900 }, () =>
      json(n++ === 0 ? pair2 : { ...pair2, refresh_token: 'r3' }),
    );
    expect(await auth.handleUnauthorized({ headers: { Authorization: `Bearer ${access1}` } })).toBe(true);
    expect(calls).toHaveLength(1);
    expect(await auth.handleUnauthorized({ headers: { 'X-Other': 'x' } })).toBe(true);
    expect(calls).toHaveLength(2);
  });

  it('a 401 from a stale token joins a refresh that is still running', async () => {
    const gate = deferred<void>();
    const { auth, calls } = await seeded(nearExpiry(), async () => {
      await gate.promise;
      return json(pair2);
    });
    const t = auth.getAccessToken();
    const h = auth.handleUnauthorized({ headers: { Authorization: `Bearer ${access1}` } });
    await new Promise((r) => setTimeout(r, 0));
    gate.resolve();
    expect(await t).toBe(access2);
    expect(await h).toBe(true);
    expect(calls).toHaveLength(1);
  });

  it('getAccessToken and handleUnauthorized running together share one flight', async () => {
    const gate = deferred<void>();
    const { auth, calls } = await seeded(nearExpiry(), async () => {
      await gate.promise;
      return json(pair2);
    });
    const all = Promise.all([auth.getAccessToken(), auth.handleUnauthorized(), auth.getAccessToken(), auth.handleUnauthorized()]);
    await new Promise((r) => setTimeout(r, 0));
    gate.resolve();
    expect(await all).toEqual([access2, true, access2, true]);
    expect(calls).toHaveLength(1);
  });

  it('a refresh 401 after a re-login during the request keeps the new session and resolves true', async () => {
    const access3 = jwt({ sub: '8', exp: now() + 900 });
    const gate = deferred<void>();
    const { auth, store, events } = await seeded({ ...nearExpiry(), deviceId: 'd1' }, async (c) => {
      if (c.url.endsWith('/auth/token/refresh')) {
        await gate.promise;
        return json({}, 401);
      }
      return json({ access_token: access3, refresh_token: 'r3', expires_in: 900, token_type: 'Bearer' });
    });
    await auth.ready();
    const h = auth.handleUnauthorized();
    await new Promise((r) => setTimeout(r, 0));
    await auth.login({});
    gate.resolve();
    expect(await h).toBe(true);
    const t = await store.get();
    expect(t?.accessToken).toBe(access3);
    expect(t?.refreshToken).toBe('r3');
    expect(auth.getState().status).toBe('authenticated');
    expect(eventTypes(events)).not.toContain('session_ended');
  });

  describe('200 {success:false} 10002 answer', () => {
    const rejected = (): Response => json({ success: false, error_code: 10002, message: 'Invalid refresh token' });

    it('after a re-login during the request keeps the new session', async () => {
      const access3 = jwt({ sub: '8', exp: now() + 900 });
      const gate = deferred<void>();
      const { auth, store, events } = await seeded({ ...nearExpiry(), deviceId: 'd1' }, async (c) => {
        if (c.url.endsWith('/auth/token/refresh')) {
          await gate.promise;
          return rejected();
        }
        return json({ access_token: access3, refresh_token: 'r3', expires_in: 900, token_type: 'Bearer' });
      });
      await auth.ready();
      const p = auth.refresh().catch((e: unknown) => e);
      await new Promise((r) => setTimeout(r, 0));
      await auth.login({});
      gate.resolve();
      await p;
      expect((await store.get())?.refreshToken).toBe('r3');
      expect(auth.getState().status).toBe('authenticated');
      expect(eventTypes(events)).not.toContain('session_ended');
    });

    it('after a logout during the request emits no second session_ended', async () => {
      const gate = deferred<void>();
      const { auth, events } = await seeded({ ...nearExpiry(), deviceId: 'd1' }, async (c) => {
        if (c.url.endsWith('/auth/token/refresh')) {
          await gate.promise;
          return rejected();
        }
        return new Response(null, { status: 204 });
      });
      await auth.ready();
      const p = auth.refresh().catch((e: unknown) => e);
      await new Promise((r) => setTimeout(r, 0));
      await auth.logout();
      const before = events.filter((e) => e.type === 'session_ended').length;
      gate.resolve();
      await p;
      expect(events.filter((e) => e.type === 'session_ended')).toHaveLength(before);
      expect(auth.getState().status).toBe('anonymous');
    });

    it('with no interference ends the session with refresh_rejected', async () => {
      const { auth, events } = await seeded({ ...nearExpiry(), deviceId: 'd1' }, () => rejected());
      await auth.ready();
      await auth.refresh().catch(() => undefined);
      expect(events.find((e) => e.type === 'session_ended')).toMatchObject({ reason: 'refresh_rejected' });
      expect(auth.getState().status).toBe('anonymous');
    });
  });
});

describe('caller-abort isolation', () => {
  it('an aborted getAccessToken waiter does not cancel the shared refresh; the other waiters get the new token', async () => {
    const gate = deferred<void>();
    const { auth, calls } = await seeded(nearExpiry(), async () => {
      await gate.promise;
      return json(pair2);
    });
    const ac = new AbortController();
    const reason = new Error('navigated away');
    const a = auth.getAccessToken({ signal: ac.signal }).catch((e: unknown) => e);
    const b = auth.getAccessToken();
    const c = auth.getAccessToken();
    await new Promise((r) => setTimeout(r, 0));
    expect(calls).toHaveLength(1);
    ac.abort(reason);
    expect(await a).toBe(reason);
    expect(calls[0]?.signal?.aborted).toBe(false);
    gate.resolve();
    expect(await b).toBe(access2);
    expect(await c).toBe(access2);
    expect(calls).toHaveLength(1);
  });

  it('an already-aborted signal rejects immediately with its reason', async () => {
    const { auth } = await seeded(nearExpiry(), () => json(pair2));
    const ac = new AbortController();
    ac.abort(new Error('early'));
    await expect(auth.getAccessToken({ signal: ac.signal })).rejects.toThrow('early');
  });

  it('a pre-aborted signal with a failing refresh starts no refresh and leaves no unhandled rejection', async () => {
    const { auth, calls } = await seeded(nearExpiry(), () => Promise.reject(new TypeError('offline')));
    const ac = new AbortController();
    ac.abort(new Error('early'));
    await expect(auth.getAccessToken({ signal: ac.signal })).rejects.toThrow('early');
    await expect(auth.handleUnauthorized({ signal: ac.signal })).rejects.toThrow('early');
    await new Promise((r) => setTimeout(r, 0));
    expect(calls).toHaveLength(0);
  });

  it('waitFor handles the shared promise even when the signal is already aborted', async () => {
    const ac = new AbortController();
    ac.abort(new Error('gone'));
    const shared = Promise.reject(new Error('refresh failed'));
    await expect(waitFor(shared, ac.signal)).rejects.toThrow('gone');
    await new Promise((r) => setTimeout(r, 0)); // an unhandled rejection of `shared` would fail the run
  });

  it('an aborted handleUnauthorized waiter does not cancel the shared refresh', async () => {
    const gate = deferred<void>();
    const { auth, calls, store } = await seeded(nearExpiry(), async () => {
      await gate.promise;
      return json(pair2);
    });
    const ac = new AbortController();
    const a = auth.handleUnauthorized({ signal: ac.signal }).catch((e: unknown) => e);
    const b = auth.handleUnauthorized();
    await new Promise((r) => setTimeout(r, 0));
    ac.abort(new Error('stop'));
    expect(await a).toBeInstanceOf(Error);
    gate.resolve();
    expect(await b).toBe(true);
    expect(calls[0]?.signal?.aborted).toBe(false);
    expect((await store.get())?.refreshToken).toBe('r2');
  });
});

describe('events', () => {
  it('refresh, refresh_failed and session_ended carry no token values', async () => {
    let n = 0;
    const { auth, events } = await seeded(nearExpiry(), () => {
      n++;
      if (n === 1) return json(pair2);
      if (n === 2) return json({ message: 'down' }, 503);
      return json({}, 401);
    });
    await auth.refresh();
    await auth.refresh().catch(() => undefined);
    await auth.refresh().catch(() => undefined);
    expect(eventTypes(events)).toEqual(['refresh', 'refresh_failed', 'refresh_failed', 'session_ended']);
    const text = JSON.stringify(events);
    for (const secret of [access1, access2, 'r1', 'r2']) expect(text).not.toContain(secret);
    const failed = events.find((e) => e.type === 'refresh_failed');
    expect(failed).toMatchObject({ status: 503 });
  });
});
