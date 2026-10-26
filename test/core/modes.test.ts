import { afterEach, describe, expect, it, vi } from 'vitest';
import { apiKey, clientCredentials, staticToken } from '../../src/core/modes';
import { createJwtAuth, userSession } from '../../src/core/create-jwt-auth';
import type { AuthEvent, AuthMode } from '../../src/core/create-jwt-auth';
import { memoryStore } from '../../src/core/stores';
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
const basic = (id: string, secret: string): string => {
  let bin = '';
  for (const b of new TextEncoder().encode(`${id}:${secret}`)) bin += String.fromCharCode(b);
  return `Basic ${btoa(bin)}`;
};

interface Call {
  url: string;
  method: string;
  headers: Record<string, string>;
  form: URLSearchParams;
}
type Responder = (call: Call, n: number) => Response | Promise<Response>;
const json = (body: unknown, status = 200): Response =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

function fakeFetch(responder: Responder): { fetch: typeof fetch; calls: Call[] } {
  const calls: Call[] = [];
  const f = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const headers: Record<string, string> = {};
    new Headers(init?.headers).forEach((v, k) => {
      headers[k] = v;
    });
    const call: Call = {
      url: String(input),
      method: init?.method ?? 'GET',
      headers,
      form: new URLSearchParams(typeof init?.body === 'string' ? init.body : ''),
    };
    calls.push(call);
    return responder(call, calls.length);
  };
  return { fetch: f as typeof fetch, calls };
}

const SECRET = 'cs-very-secret';
const tokenN = (n: number): string => `spoat_tok${n}.${'a'.repeat(64)}`;
const ok = (_c: Call, n: number): Response => json({ access_token: tokenN(n), token_type: 'Bearer', expires_in: 3600 });

function setup(mode: AuthMode, responder: Responder = ok, extra: { refreshAheadSeconds?: number } = {}) {
  const { fetch, calls } = fakeFetch(responder);
  const events: AuthEvent[] = [];
  const auth = createJwtAuth({
    baseUrl: 'http://api.test',
    endpoints: {},
    mode,
    fetch,
    onEvent: (e) => events.push(e),
    ...extra,
  });
  return { auth, calls, events };
}
const cc = (o: Partial<Parameters<typeof clientCredentials>[0]> = {}): AuthMode =>
  clientCredentials({ clientId: 'my-id', clientSecret: SECRET, scope: 'read write', ...o });

afterEach(() => {
  vi.useRealTimers();
});

describe('clientCredentials', () => {
  it('posts grant_type and scope form-encoded with HTTP Basic to endpoints.oauthToken', async () => {
    const { auth, calls } = setup(cc());
    expect(await auth.getAccessToken()).toBe(tokenN(1));
    expect(calls).toHaveLength(1);
    const c = calls[0]!;
    expect(c.url).toBe('http://api.test/oauth/token');
    expect(c.method).toBe('POST');
    expect(c.headers['content-type']).toBe('application/x-www-form-urlencoded');
    expect(c.headers.authorization).toBe(basic('my-id', SECRET));
    expect(c.form.get('grant_type')).toBe('client_credentials');
    expect(c.form.get('scope')).toBe('read write');
    expect(c.form.has('client_secret')).toBe(false);
    expect(await auth.getHeaders()).toEqual({ Authorization: `Bearer ${tokenN(1)}` });
    expect(calls).toHaveLength(1);
  });

  it('Basic encoding is UTF-8 safe', async () => {
    const { auth, calls } = setup(cc({ clientId: 'idé', clientSecret: 'sécrèt' }));
    await auth.getAccessToken();
    expect(calls[0]!.headers.authorization).toBe(basic('idé', 'sécrèt'));
  });

  it("auth: 'body' sends client_id/client_secret in the body and no Authorization", async () => {
    const { auth, calls } = setup(cc({ auth: 'body' }));
    await auth.getAccessToken();
    const c = calls[0]!;
    expect(c.headers.authorization).toBeUndefined();
    expect(c.form.get('client_id')).toBe('my-id');
    expect(c.form.get('client_secret')).toBe(SECRET);
    expect(c.form.get('grant_type')).toBe('client_credentials');
  });

  it('tokenUrl overrides endpoints.oauthToken', async () => {
    const { auth, calls } = setup(cc({ tokenUrl: 'https://idp.test/t' }));
    await auth.getAccessToken();
    expect(calls[0]!.url).toBe('https://idp.test/t');
  });

  it('state is authenticated with null claims for an opaque token; anonymous before', async () => {
    const { auth } = setup(cc());
    await auth.ready();
    expect(auth.getState().status).toBe('anonymous');
    await auth.getAccessToken();
    expect(auth.getState().status).toBe('authenticated');
    expect(auth.getState().claims).toBeNull();
  });

  it('decodes claims when the token is a JWT', async () => {
    const t = jwt({ sub: 'svc', exp: 9999999999, scopes: ['a'] });
    const { auth } = setup(cc(), () => json({ access_token: t, expires_in: 3600 }));
    await auth.getAccessToken();
    expect(auth.getState().claims?.sub).toBe('svc');
  });

  it('re-fetches refreshAheadSeconds before expiry', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-01-01T00:00:00Z'));
    const { auth, calls } = setup(cc(), ok, { refreshAheadSeconds: 60 });
    expect(await auth.getAccessToken()).toBe(tokenN(1));
    vi.setSystemTime(Date.now() + 3539_000); // 61s left
    expect(await auth.getAccessToken()).toBe(tokenN(1));
    expect(calls).toHaveLength(1);
    vi.setSystemTime(Date.now() + 2_000); // 59s left
    expect(await auth.getAccessToken()).toBe(tokenN(2));
    expect(calls).toHaveLength(2);
  });

  it('expires_in: 0 falls back to defaultTtlSeconds (J1)', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-01-01T00:00:00Z'));
    const { auth, calls } = setup(cc({ defaultTtlSeconds: 600 }), (_c, n) =>
      json({ access_token: tokenN(n), expires_in: 0 }),
    );
    await auth.getAccessToken();
    vi.setSystemTime(Date.now() + 500_000);
    expect(await auth.getAccessToken()).toBe(tokenN(1));
    expect(calls).toHaveLength(1);
    vi.setSystemTime(Date.now() + 50_000); // 50s left < 60
    expect(await auth.getAccessToken()).toBe(tokenN(2));
  });

  it('defaultTtlSeconds defaults to 3600 when expires_in is missing', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-01-01T00:00:00Z'));
    const { auth, calls } = setup(cc(), (_c, n) => json({ access_token: tokenN(n) }));
    await auth.getAccessToken();
    vi.setSystemTime(Date.now() + 3000_000);
    await auth.getAccessToken();
    expect(calls).toHaveLength(1);
    vi.setSystemTime(Date.now() + 560_000);
    expect(await auth.getAccessToken()).toBe(tokenN(2));
  });

  it('50 concurrent getAccessToken calls share one token request', async () => {
    const { auth, calls } = setup(cc());
    const all = await Promise.all(Array.from({ length: 50 }, () => auth.getAccessToken()));
    expect(new Set(all)).toEqual(new Set([tokenN(1)]));
    expect(calls).toHaveLength(1);
  });

  it('a failed fetch does not stick: the next call retries', async () => {
    const { auth, calls } = setup(cc(), (c, n) => (n === 1 ? new Response('boom', { status: 503 }) : ok(c, n)));
    await expect(auth.getAccessToken()).rejects.toBeInstanceOf(SpAuthError);
    expect(auth.getState().status).toBe('anonymous');
    expect(await auth.getAccessToken()).toBe(tokenN(2));
    expect(calls).toHaveLength(2);
  });

  it('handleUnauthorized re-fetches and resolves true', async () => {
    const { auth, calls } = setup(cc());
    const t1 = await auth.getAccessToken();
    expect(await auth.handleUnauthorized({ headers: { Authorization: `Bearer ${t1}` } })).toBe(true);
    expect(calls).toHaveLength(2);
    expect(await auth.getAccessToken()).toBe(tokenN(2));
  });

  it('handleUnauthorized with a stale bearer resolves true without a request', async () => {
    const { auth, calls } = setup(cc());
    await auth.getAccessToken();
    expect(await auth.handleUnauthorized({ headers: { authorization: 'bearer old-token' } })).toBe(true);
    expect(calls).toHaveLength(1);
  });

  it('concurrent 401s share one re-fetch', async () => {
    const { auth, calls } = setup(cc());
    const t1 = await auth.getAccessToken();
    const h = { Authorization: `Bearer ${t1}` };
    const r = await Promise.all([auth.handleUnauthorized({ headers: h }), auth.handleUnauthorized({ headers: h })]);
    expect(r).toEqual([true, true]);
    expect(calls).toHaveLength(2);
  });

  it.each(['invalid_client', 'invalid_scope'])('400/401 %s becomes SpAuthError with that code, token cleared', async (code) => {
    const { auth, events } = setup(cc(), (_c, n) =>
      n === 1 ? ok(_c, n) : json({ error: code, error_description: 'nope' }, code === 'invalid_client' ? 401 : 400),
    );
    await auth.getAccessToken();
    const h = { Authorization: `Bearer ${tokenN(1)}` };
    const err = await auth.handleUnauthorized({ headers: h }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(SpAuthError);
    expect((err as SpAuthError).code).toBe(code);
    expect(auth.getState().status).toBe('anonymous');
    expect(events.map((e) => e.type)).toEqual(['token_fetched', 'token_failed']);
  });

  it('network failure rethrows and leaves state unchanged', async () => {
    const { auth } = setup(cc(), (c, n) => {
      if (n === 1) return ok(c, n);
      throw new TypeError('offline');
    });
    await auth.getAccessToken();
    const before = auth.getState();
    await expect(auth.handleUnauthorized({ headers: { Authorization: `Bearer ${tokenN(1)}` } })).rejects.toMatchObject({
      code: 'network',
    });
    expect(auth.getState()).toBe(before);
  });

  it('a proactive-refresh failure returns the still-valid token', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-01-01T00:00:00Z'));
    const { auth } = setup(cc(), (c, n) => (n === 1 ? ok(c, n) : new Response('x', { status: 500 })));
    await auth.getAccessToken();
    vi.setSystemTime(Date.now() + 3580_000);
    expect(await auth.getAccessToken()).toBe(tokenN(1));
    vi.setSystemTime(Date.now() + 30_000); // expired
    await expect(auth.getAccessToken()).rejects.toBeInstanceOf(SpAuthError);
  });

  it('aborting a waiter does not cancel the shared fetch; pre-aborted signal leaves no unhandled rejection', async () => {
    const unhandled = vi.fn();
    process.on?.('unhandledRejection', unhandled);
    let release: (r: Response) => void = () => undefined;
    const { auth, calls } = setup(cc(), () => new Promise<Response>((r) => (release = r)));
    const ac = new AbortController();
    const aborted = auth.getAccessToken({ signal: ac.signal });
    const other = auth.getAccessToken();
    const pre = new AbortController();
    pre.abort(new Error('pre'));
    await expect(auth.getAccessToken({ signal: pre.signal })).rejects.toThrow('pre');
    ac.abort(new Error('gone'));
    await expect(aborted).rejects.toThrow('gone');
    release(ok({} as Call, 1));
    expect(await other).toBe(tokenN(1));
    expect(calls).toHaveLength(1);
    await new Promise((r) => setTimeout(r, 0));
    process.off?.('unhandledRejection', unhandled);
    expect(unhandled).not.toHaveBeenCalled();
  });

  it('logout clears the in-memory token with no network call', async () => {
    const { auth, calls } = setup(cc());
    await auth.getAccessToken();
    await auth.logout();
    expect(calls).toHaveLength(1);
    expect(auth.getState().status).toBe('anonymous');
    expect(await auth.getAccessToken()).toBe(tokenN(2)); // next use fetches anew
  });

  it('never leaks the secret or token via events, errors or state', async () => {
    const { auth, events } = setup(cc(), (c, n) =>
      n === 1 ? ok(c, n) : json({ error: 'invalid_client', error_description: 'Client authentication failed' }, 401),
    );
    const t = (await auth.getAccessToken()) as string;
    const err = await auth.handleUnauthorized({ headers: { Authorization: `Bearer ${t}` } }).catch((e: unknown) => e);
    const blob = JSON.stringify(events) + (err as Error).message + JSON.stringify(auth.getState());
    expect(blob).not.toContain(SECRET);
    expect(blob).not.toContain(t);
    expect(events).toHaveLength(2);
  });

  it('touches no browser globals and works without document', async () => {
    expect((globalThis as { document?: unknown }).document).toBeUndefined();
    const { auth } = setup(cc());
    await expect(auth.getAccessToken()).resolves.toBeTruthy();
  });
});

describe('apiKey', () => {
  const KEY = 'spk_live_abcdef123456';
  it('sends Bearer <key>, is authenticated at once, makes no request', async () => {
    const { auth, calls, events } = setup(apiKey(KEY));
    expect(await auth.getHeaders()).toEqual({ Authorization: `Bearer ${KEY}` });
    expect(await auth.getAccessToken()).toBe(KEY);
    expect(auth.getState().status).toBe('authenticated');
    expect(auth.getState().claims).toBeNull();
    expect(calls).toHaveLength(0);
    expect(events).toEqual([]);
  });

  it('a 401 is final, with or without headers', async () => {
    const { auth, calls } = setup(apiKey(KEY));
    expect(await auth.handleUnauthorized()).toBe(false);
    expect(await auth.handleUnauthorized({ headers: { Authorization: `Bearer ${KEY}` } })).toBe(false);
    expect(calls).toHaveLength(0);
  });

  it('is authenticated synchronously and never leaks the key', async () => {
    const { auth, events } = setup(apiKey(KEY));
    expect(auth.getState().status).toBe('authenticated');
    await auth.logout();
    expect(JSON.stringify(events) + JSON.stringify(auth.getState())).not.toContain(KEY);
    expect(auth.getState().status).toBe('anonymous');
  });

  it('rejects an empty key', () => {
    expect(() => apiKey('')).toThrow(SpAuthError);
  });
});

describe('staticToken', () => {
  it('calls getToken on every getHeaders / getAccessToken (no caching)', async () => {
    const getToken = vi.fn(() => 'tok-1');
    const { auth, calls } = setup(staticToken(getToken));
    await auth.getHeaders();
    await auth.getHeaders();
    await auth.getAccessToken();
    expect(getToken).toHaveBeenCalledTimes(3);
    expect(await auth.getHeaders()).toEqual({ Authorization: 'Bearer tok-1' });
    expect(calls).toHaveLength(0);
  });

  it('follows a changing token and supports async getters', async () => {
    let t: string | undefined = 'a';
    const { auth } = setup(staticToken(async () => t));
    expect(await auth.getAccessToken()).toBe('a');
    t = 'b';
    expect(await auth.getAccessToken()).toBe('b');
  });

  it.each([undefined, null, ''])('%s token gives anonymous headers {}', async (v) => {
    const { auth } = setup(staticToken(() => v));
    expect(await auth.getHeaders()).toEqual({});
    expect(await auth.getAccessToken()).toBeNull();
    expect(auth.getState().status).toBe('anonymous');
  });

  it('handleUnauthorized resolves false', async () => {
    const { auth } = setup(staticToken(() => 'x'));
    expect(await auth.handleUnauthorized({ headers: { Authorization: 'Bearer y' } })).toBe(false);
  });

  it('decodes JWT claims into getState() on demand; opaque tokens give null claims', async () => {
    const { auth } = setup(staticToken(() => jwt({ sub: '9', exp: 9999999999, company_id: 5 })));
    await auth.getHeaders();
    expect(auth.getState().status).toBe('authenticated');
    expect(auth.getState().claims?.sub).toBe('9');
    expect(auth.getState().companyId).toBe('5');
    const o = setup(staticToken(() => 'opaque'));
    await o.auth.getHeaders();
    expect(o.auth.getState().claims).toBeNull();
  });

  it('two instances with different tokens never share state', async () => {
    const a = setup(staticToken(() => jwt({ sub: 'alice', exp: 9999999999 }))).auth;
    const b = setup(staticToken(() => jwt({ sub: 'bob', exp: 9999999999 }))).auth;
    const [ha, hb] = await Promise.all([a.getHeaders(), b.getHeaders()]);
    expect(ha.Authorization).not.toBe(hb.Authorization);
    expect(a.getState().claims?.sub).toBe('alice');
    expect(b.getState().claims?.sub).toBe('bob');
  });

  it('never stores or emits the token', async () => {
    const TOK = 'tok-secret-123';
    const { auth, events } = setup(staticToken(() => TOK));
    await auth.getHeaders();
    await auth.logout();
    expect(JSON.stringify(events) + JSON.stringify(auth.getState())).not.toContain(TOK);
  });
});

describe('server rule', () => {
  it('userSession with a memory store and no document does not throw and is anonymous', async () => {
    expect((globalThis as { document?: unknown }).document).toBeUndefined();
    const auth = createJwtAuth({ baseUrl: 'http://api.test', endpoints: {}, mode: userSession({ storage: memoryStore() }) });
    await auth.ready();
    expect(auth.getState().status).toBe('anonymous');
    expect(await auth.getHeaders()).toEqual({});
    auth.dispose?.();
  });
});
