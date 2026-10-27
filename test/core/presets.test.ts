import { describe, expect, it } from 'vitest';
import { createJwtAuth, userSession } from '../../src/core/create-jwt-auth';
import type { AuthEvent } from '../../src/core/create-jwt-auth';
import { presets } from '../../src/core/presets';
import { memoryStore } from '../../src/core/stores';
import type { Tokens } from '../../src/core/stores';
import * as api from '../../src/index';

function b64url(s: string): string {
  const bytes = new TextEncoder().encode(s);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function jwt(payload: Record<string, unknown>): string {
  return `${b64url(JSON.stringify({ alg: 'none', typ: 'JWT' }))}.${b64url(JSON.stringify(payload))}.sig`;
}

const nowSec = (): number => Math.floor(Date.now() / 1000);

function access(extra: Record<string, unknown> = {}, ttl = 900): string {
  return jwt({ sub: 'u1', exp: nowSec() + ttl, scopes: ['a'], ...extra });
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

async function settle(n = 20): Promise<void> {
  for (let i = 0; i < n; i++) await Promise.resolve();
}

interface Call {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: unknown;
}

function recorder(handler: (c: Call) => Response | Promise<Response>): { fetch: typeof fetch; calls: Call[] } {
  const calls: Call[] = [];
  const f = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const c: Call = {
      url: String(input),
      method: init?.method ?? 'GET',
      headers: { ...(init?.headers as Record<string, string>) },
      body: typeof init?.body === 'string' ? JSON.parse(init.body) : undefined,
    };
    calls.push(c);
    return handler(c);
  };
  return { fetch: f as typeof fetch, calls };
}

const BASE = 'https://api.test/api';

describe('presets', () => {
  it('has the exact documented shapes', () => {
    expect(presets.spJwtTest).toEqual({
      endpoints: { login: '/auth/login', refresh: '/auth/refresh', logout: '/auth/logout', whoami: '/me' },
      unwrap: 'raw',
    });
    expect(presets.spSaas).toEqual({
      endpoints: {
        login: '/auth/login',
        secondFactor: '/auth/login/2fa',
        refresh: '/auth/refresh',
        logout: '/auth/logout',
        whoami: '/auth/whoami',
        switchCompany: '/auth/impersonate_in',
        forgotPassword: '/auth/forgot-password',
        resetPassword: '/auth/reset-password',
        resendVerification: '/auth/resend-email-verification',
      },
      unwrap: 'sp-laravel-api',
    });
  });

  it('are frozen, not mutated by createJwtAuth, and exported from the index', () => {
    const before = JSON.stringify(presets);
    expect(Object.isFrozen(presets)).toBe(true);
    expect(Object.isFrozen(presets.spJwtTest)).toBe(true);
    expect(Object.isFrozen(presets.spSaas.endpoints)).toBe(true);
    const auth = createJwtAuth({ baseUrl: BASE, ...presets.spJwtTest, mode: userSession({ storage: memoryStore() }) });
    auth.dispose?.();
    expect(JSON.stringify(presets)).toBe(before);
    expect(api.presets).toBe(presets);
    expect('baseUrl' in presets.spJwtTest).toBe(false);
    expect('mode' in presets.spSaas).toBe(false);
  });

  it('spJwtTest logs in against the {user, token} shape', async () => {
    const at = access();
    const { fetch, calls } = recorder(() =>
      json({ user: { id: 1 }, token: { token_type: 'Bearer', expires_in: 900, access_token: at, refresh_token: 'r0' } }),
    );
    const store = memoryStore();
    const auth = createJwtAuth({ baseUrl: BASE, ...presets.spJwtTest, mode: userSession({ storage: store }), fetch });
    expect(await auth.login({ email: 'a', password: 'b' })).toEqual({ status: 'authenticated' });
    expect(calls[0]?.url).toBe(`${BASE}/auth/login`);
    expect(auth.getState().status).toBe('authenticated');
    expect((await store.get())?.refreshToken).toBe('r0');
    auth.dispose?.();
  });

  it('spSaas logs in against the envelope and handles the un-enveloped 2FA step', async () => {
    const at = access({ company_id: 7 });
    const { fetch, calls } = recorder((c) => {
      if (c.url.endsWith('/auth/login')) return json({ requires_2fa: true, '2fa_token': 'T' });
      return json({ success: true, data: { token_type: 'Bearer', expires_in: 900, access_token: at, refresh_token: 'r0', company_id: 7 } });
    });
    const auth = createJwtAuth({ baseUrl: BASE, ...presets.spSaas, mode: userSession({ storage: memoryStore() }), fetch });
    const res = await auth.login({ email: 'a', password: 'b' });
    expect(res).toEqual({ status: 'second_factor_required', challenge: { kind: '2fa_token', token: 'T' } });
    expect(auth.getState().status).toBe('anonymous');
    if (res.status !== 'second_factor_required') throw new Error('unreachable');
    await auth.verifySecondFactor(res.challenge, '123456');
    expect(calls[1]?.url).toBe(`${BASE}/auth/login/2fa`);
    expect(calls[1]?.body).toEqual({ '2fa_token': 'T', otp: '123456' });
    expect(auth.getState().companyId).toBe('7');
    auth.dispose?.();
  });
});

describe('whoami', () => {
  it('throws not_configured when endpoints.whoami is unset', async () => {
    const auth = createJwtAuth({
      baseUrl: BASE,
      endpoints: { login: '/auth/login' },
      mode: userSession({ storage: memoryStore() }),
    });
    await expect(auth.whoami()).rejects.toMatchObject({ code: 'not_configured', module: 'core' });
    auth.dispose?.();
  });

  it('GETs with the bearer, unwraps, caches the user in state and notifies', async () => {
    const at = access();
    const store = memoryStore();
    await store.set({ accessToken: at, refreshToken: 'r0', expiresAt: nowSec() + 900 });
    const { fetch, calls } = recorder(() => json({ success: true, data: { id: 9, name: 'Ann' } }));
    const auth = createJwtAuth({ baseUrl: BASE, ...presets.spSaas, mode: userSession({ storage: store }), fetch });
    await auth.ready();
    let notified = 0;
    auth.subscribe(() => notified++);
    const user = await auth.whoami();
    expect(user).toEqual({ id: 9, name: 'Ann' });
    expect(calls[0]).toMatchObject({ url: `${BASE}/auth/whoami`, method: 'GET' });
    expect(calls[0]?.headers.Authorization).toBe(`Bearer ${at}`);
    expect(auth.getState().user).toEqual({ id: 9, name: 'Ann' });
    expect(notified).toBe(1);
    const snap = auth.getState();
    expect(auth.getState()).toBe(snap);
    auth.dispose?.();
  });

  it('retries once after a 401 using the refreshed token', async () => {
    const old = access({ jti: 'old' });
    const fresh = access({ jti: 'fresh' });
    const store = memoryStore();
    await store.set({ accessToken: old, refreshToken: 'r0', expiresAt: nowSec() + 900 });
    const { fetch, calls } = recorder((c) => {
      if (c.url.endsWith('/auth/refresh')) {
        return json({ success: true, data: { token_type: 'Bearer', expires_in: 900, access_token: fresh, refresh_token: 'r1' } });
      }
      return c.headers.Authorization === `Bearer ${fresh}` ? json({ success: true, data: { id: 1 } }) : json({ message: 'no' }, 401);
    });
    const auth = createJwtAuth({ baseUrl: BASE, ...presets.spSaas, mode: userSession({ storage: store }), fetch });
    expect(await auth.whoami()).toEqual({ id: 1 });
    expect(calls.map((c) => c.url.replace(BASE, ''))).toEqual(['/auth/whoami', '/auth/refresh', '/auth/whoami']);
    auth.dispose?.();
  });

  it('does not retry twice and rejects with the 401 when the session is gone', async () => {
    const store = memoryStore();
    await store.set({ accessToken: access(), refreshToken: 'r0', expiresAt: nowSec() + 900 });
    const { fetch, calls } = recorder(() => json({ message: 'no' }, 401));
    const auth = createJwtAuth({ baseUrl: BASE, ...presets.spJwtTest, mode: userSession({ storage: store }), fetch });
    await expect(auth.whoami()).rejects.toMatchObject({ status: 401 });
    // whoami 401 -> refresh 401 (session ended) -> no retry
    expect(calls.map((c) => c.url.replace(BASE, ''))).toEqual(['/me', '/auth/refresh']);
    auth.dispose?.();
  });
});

/** A fake SaaS host that rotates refresh tokens and 401s on any reuse. */
function saasHost(): { fetch: typeof fetch; presented: string[]; reused: string[] } {
  let valid = 'r0';
  let n = 0;
  const presented: string[] = [];
  const reused: string[] = [];
  const f = recorder(async (c) => {
    const rt = (c.body as { refresh_token?: string } | undefined)?.refresh_token;
    if (c.url.endsWith('/auth/refresh') || c.url.endsWith('/auth/impersonate_in')) {
      await settle(5);
      presented.push(String(rt));
      if (rt !== valid) {
        reused.push(String(rt));
        return json({ success: false }, 401);
      }
      n++;
      valid = `r${n}`;
      const company = (c.body as { company_id?: number }).company_id ?? 1;
      return json({
        success: true,
        data: { token_type: 'Bearer', expires_in: 900, access_token: access({ company_id: company, n }), refresh_token: valid },
      });
    }
    return json({ success: true, data: {} });
  });
  return { fetch: f.fetch, presented, reused };
}

async function loggedIn(store = memoryStore()): Promise<{ store: ReturnType<typeof memoryStore> }> {
  await store.set({ accessToken: access({ company_id: 1 }), refreshToken: 'r0', expiresAt: nowSec() + 900, deviceId: 'dev' });
  return { store };
}

describe('switchCompany', () => {
  it('posts {company_id, refresh_token}, stores the pair, updates companyId and lastCompanyId', async () => {
    const { store } = await loggedIn();
    const events: AuthEvent[] = [];
    const calls = recorder(async (c) => {
      expect(c.url).toBe(`${BASE}/auth/impersonate_in`);
      return json({
        success: true,
        data: { token_type: 'Bearer', expires_in: 900, access_token: access({ company_id: 5 }), refresh_token: 'r9' },
      });
    });
    const auth = createJwtAuth({
      baseUrl: BASE,
      ...presets.spSaas,
      mode: userSession({ storage: store }),
      fetch: calls.fetch,
      device: { name: 'Test' },
      onEvent: (e) => events.push(e),
    });
    await auth.ready();
    expect(auth.getState().companyId).toBe('1');
    await auth.switchCompany(5);
    expect(calls.calls[0]?.method).toBe('POST');
    expect(calls.calls[0]?.body).toEqual({ company_id: 5, refresh_token: 'r0' });
    expect(calls.calls[0]?.headers['X-Device-Id']).toBe('dev');
    expect(calls.calls[0]?.headers['X-Device-Name']).toBe('Test');
    expect(auth.getState().companyId).toBe('5');
    const t = (await store.get()) as Tokens;
    expect(t.refreshToken).toBe('r9');
    expect(t.lastCompanyId).toBe('5');
    expect(t.deviceId).toBe('dev');
    auth.dispose?.();
  });

  it('throws not_configured without endpoints.switchCompany', async () => {
    const { store } = await loggedIn();
    const auth = createJwtAuth({ baseUrl: BASE, ...presets.spJwtTest, mode: userSession({ storage: store }) });
    await expect(auth.switchCompany(2)).rejects.toMatchObject({ code: 'not_configured', module: 'core' });
    auth.dispose?.();
  });

  it('keeps the existing tokens and throws unknown when the response has no valid pair', async () => {
    const { store } = await loggedIn();
    const before = await store.get();
    const { fetch } = recorder(() => json({ success: true, data: { ok: true } }));
    const auth = createJwtAuth({ baseUrl: BASE, ...presets.spSaas, mode: userSession({ storage: store }), fetch });
    await expect(auth.switchCompany(2)).rejects.toMatchObject({ code: 'unknown' });
    expect(await store.get()).toEqual(before);
    expect(auth.getState().companyId).toBe('1');
    auth.dispose?.();
  });

  it('two simultaneous switchCompany calls never present the same refresh token', async () => {
    const { store } = await loggedIn();
    const host = saasHost();
    const auth = createJwtAuth({ baseUrl: BASE, ...presets.spSaas, mode: userSession({ storage: store }), fetch: host.fetch });
    await Promise.all([auth.switchCompany(2), auth.switchCompany(3)]);
    expect(host.presented).toEqual(['r0', 'r1']);
    expect(host.reused).toEqual([]);
    expect((await store.get())?.refreshToken).toBe('r2');
    expect(auth.getState().companyId).toBe('3');
    auth.dispose?.();
  });

  it.each([
    ['switch first', true],
    ['refresh first', false],
  ])('a concurrent switchCompany and refresh rotate strictly (%s)', async (_n, switchFirst) => {
    const { store } = await loggedIn();
    const host = saasHost();
    const auth = createJwtAuth({ baseUrl: BASE, ...presets.spSaas, mode: userSession({ storage: store }), fetch: host.fetch });
    const ps = switchFirst
      ? [auth.switchCompany(4), auth.refresh()]
      : [auth.refresh(), auth.switchCompany(4)];
    await Promise.all(ps);
    expect(host.presented).toEqual(['r0', 'r1']);
    expect(host.reused).toEqual([]);
    expect(auth.getState().status).toBe('authenticated');
    auth.dispose?.();
  });

  it('works with crossTab disabled too', async () => {
    const { store } = await loggedIn();
    const host = saasHost();
    const auth = createJwtAuth({
      baseUrl: BASE,
      ...presets.spSaas,
      mode: userSession({ storage: store, crossTab: false }),
      fetch: host.fetch,
    });
    await Promise.all([auth.switchCompany(2), auth.refresh(), auth.switchCompany(3)]);
    expect(host.presented).toEqual(['r0', 'r1', 'r2']);
    expect(host.reused).toEqual([]);
    auth.dispose?.();
  });
});

describe('scopes', () => {
  async function withScopes(scopes: unknown): Promise<ReturnType<typeof createJwtAuth>> {
    const store = memoryStore();
    await store.set({ accessToken: access({ scopes }), refreshToken: 'r0', expiresAt: nowSec() + 900 });
    const auth = createJwtAuth({ baseUrl: BASE, endpoints: {}, mode: userSession({ storage: store }) });
    await auth.ready();
    return auth;
  }

  it('* satisfies any scope', async () => {
    const auth = await withScopes(['*']);
    expect(auth.hasScope('a')).toBe(true);
    expect(auth.hasAllScopes(['a', 'b'])).toBe(true);
    expect(auth.hasAnyScope(['zzz'])).toBe(true);
    auth.dispose?.();
  });

  it('checks exact scopes', async () => {
    const auth = await withScopes(['a']);
    expect(auth.hasScope('a')).toBe(true);
    expect(auth.hasScope('b')).toBe(false);
    expect(auth.hasAllScopes(['a', 'b'])).toBe(false);
    expect(auth.hasAllScopes(['a'])).toBe(true);
    expect(auth.hasAnyScope(['b', 'a'])).toBe(true);
    expect(auth.hasAnyScope(['b', 'c'])).toBe(false);
    auth.dispose?.();
  });

  it('handles empty arrays', async () => {
    const auth = await withScopes(['a']);
    expect(auth.hasAllScopes([])).toBe(true);
    expect(auth.hasAnyScope([])).toBe(false);
    auth.dispose?.();
  });

  it('is false for everything when anonymous or the token is opaque, and never throws', async () => {
    const anon = createJwtAuth({ baseUrl: BASE, endpoints: {}, mode: userSession({ storage: memoryStore() }) });
    expect(anon.hasScope('a')).toBe(false);
    await anon.ready();
    expect(anon.hasScope('a')).toBe(false);
    expect(anon.hasAllScopes([])).toBe(false);
    expect(anon.hasAnyScope(['a'])).toBe(false);
    anon.dispose?.();

    const store = memoryStore();
    await store.set({ accessToken: 'opaque-token', refreshToken: 'r', expiresAt: nowSec() + 900 });
    const opaque = createJwtAuth({ baseUrl: BASE, endpoints: {}, mode: userSession({ storage: store }) });
    await opaque.ready();
    expect(opaque.hasScope('a')).toBe(false);
    expect(opaque.hasAllScopes(['a'])).toBe(false);
    opaque.dispose?.();
  });
});
