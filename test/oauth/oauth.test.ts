import { describe, expect, it } from 'vitest';
import { createJwtAuth, memoryStore, SpAuthError, userSession } from '../../src';
import type { AuthEvent, JwtAuth, TokenStore, Unwrap } from '../../src';
import { oauth, oauthAuthorizationCode } from '../../src/oauth';
import type { PendingLogin, PendingStore } from '../../src/oauth';

function b64url(s: string): string {
  let bin = '';
  for (const b of new TextEncoder().encode(s)) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function jwt(payload: Record<string, unknown>): string {
  return `${b64url(JSON.stringify({ alg: 'none', typ: 'JWT' }))}.${b64url(JSON.stringify(payload))}.sig`;
}
const now = (): number => Math.floor(Date.now() / 1000);
const ACCESS = jwt({ sub: '7', exp: now() + 900 });
const REFRESH = 'rt-oauth-secret-never-in-errors';
const SECRET = 'client-secret-never-in-errors';
const CODE = 'auth-code-never-in-errors';

function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } });
}

interface Call {
  method: string;
  path: string;
  url: string;
  headers: Headers;
  body: string | undefined;
  credentials: RequestCredentials | undefined;
}
type Handler = (c: Call) => Response | Promise<Response>;

function makeFetch(handler: Handler, calls: Call[]): typeof fetch {
  return (async (input: string | URL, init?: RequestInit): Promise<Response> => {
    const c: Call = {
      method: init?.method ?? 'GET',
      path: new URL(String(input)).pathname,
      url: String(input),
      headers: new Headers(init?.headers),
      body: typeof init?.body === 'string' ? init.body : undefined,
      credentials: init?.credentials,
    };
    calls.push(c);
    return handler(c);
  }) as unknown as typeof fetch;
}

const tokenOk = (): Response => json({ access_token: ACCESS, refresh_token: REFRESH, expires_in: 900, token_type: 'Bearer' });

function memPending(): PendingStore & { current: PendingLogin | null; history: (PendingLogin | null)[] } {
  const s = {
    current: null as PendingLogin | null,
    history: [] as (PendingLogin | null)[],
    get: () => Promise.resolve(s.current),
    set: (v: PendingLogin | null) => {
      s.current = v;
      s.history.push(v);
      return Promise.resolve();
    },
  };
  return s;
}

interface Setup {
  mode: ReturnType<typeof oauthAuthorizationCode>;
  auth: JwtAuth;
  store: TokenStore;
  pending: ReturnType<typeof memPending>;
  calls: Call[];
  events: AuthEvent[];
}

function setup(
  handler: Handler = () => tokenOk(),
  o: {
    cookie?: boolean;
    clientSecret?: string;
    tokenUrl?: string;
    authorizeUrl?: string;
    scope?: string | string[];
    unwrap?: Unwrap;
    endpoints?: Record<string, string>;
  } = {},
): Setup {
  const calls: Call[] = [];
  const store = memoryStore();
  const pending = memPending();
  const events: AuthEvent[] = [];
  const mode = oauthAuthorizationCode({
    clientId: 'app-1',
    redirectUri: 'https://app.example.com/cb',
    scope: o.scope ?? 'read write',
    authorizeUrl: o.authorizeUrl ?? 'https://api.example.com/oauth/authorize',
    pendingStore: pending,
    ...(o.tokenUrl ? { tokenUrl: o.tokenUrl } : {}),
    ...(o.clientSecret ? { clientSecret: o.clientSecret } : {}),
    session: { crossTab: false, storage: store, ...(o.cookie ? { transport: 'cookie' as const } : {}) },
  });
  const auth = createJwtAuth({
    baseUrl: 'https://api.example.com',
    endpoints: { ...(o.endpoints ?? {}) },
    mode,
    fetch: makeFetch(handler, calls),
    ...(o.unwrap ? { unwrap: o.unwrap } : {}),
    onEvent: (e) => events.push(e),
    device: { id: 'dev-1', name: 'Laptop' },
  });
  return { mode, auth, store, pending, calls, events };
}

async function caught(p: Promise<unknown>): Promise<SpAuthError> {
  try {
    await p;
  } catch (e) {
    expect(e).toBeInstanceOf(SpAuthError);
    return e as SpAuthError;
  }
  throw new Error('expected rejection');
}

function params(url: string): URLSearchParams {
  return new URL(url).searchParams;
}
function callback(state: string, extra: Record<string, string> = { code: CODE }): string {
  return `https://app.example.com/cb?${new URLSearchParams({ ...extra, state }).toString()}`;
}

describe('oauthAuthorizationCode.beginLogin', () => {
  it('builds the authorize URL: S256, state, challenge, never plain', async () => {
    const s = setup();
    const url = await s.mode.beginLogin();
    const u = new URL(url);
    expect(`${u.origin}${u.pathname}`).toBe('https://api.example.com/oauth/authorize');
    const p = u.searchParams;
    expect(p.get('response_type')).toBe('code');
    expect(p.get('client_id')).toBe('app-1');
    expect(p.get('redirect_uri')).toBe('https://app.example.com/cb');
    expect(p.get('scope')).toBe('read write');
    expect(p.get('code_challenge_method')).toBe('S256');
    expect(p.getAll('code_challenge_method')).toEqual(['S256']);
    expect(url).not.toMatch(/plain/);
    expect(p.get('state')).toMatch(/^[A-Za-z0-9_-]{43,}$/); // >= 256 bits as base64url
    expect(p.get('code_challenge')).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(p.has('code_verifier')).toBe(false);
    expect(s.calls).toHaveLength(0);
  });

  it('the challenge is the S256 of the persisted verifier, and the record holds the same state', async () => {
    const s = setup();
    const url = await s.mode.beginLogin();
    const { pkceChallenge } = await import('../../src/oauth');
    expect(s.pending.current).not.toBeNull();
    expect(s.pending.current?.state).toBe(params(url).get('state'));
    expect(await pkceChallenge(s.pending.current?.verifier ?? '')).toBe(params(url).get('code_challenge'));
    expect(s.pending.current?.verifier).toMatch(/^[A-Za-z0-9\-._~]{43,128}$/);
  });

  it('preserves an existing query string, encodes values, joins an array scope, and is fresh each time', async () => {
    const s = setup(undefined, { authorizeUrl: 'https://api.example.com/oauth/authorize?tenant=a%20b', scope: ['read', 'write:x'] });
    const a = await s.mode.beginLogin();
    const b = await s.mode.beginLogin();
    expect(params(a).get('tenant')).toBe('a b');
    expect(params(a).get('scope')).toBe('read write:x');
    expect(a).toContain('redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb');
    expect(a).toContain('scope=read%20write%3Ax');
    expect(params(a).get('state')).not.toBe(params(b).get('state'));
    expect(params(a).get('code_challenge')).not.toBe(params(b).get('code_challenge'));
  });

  it('throws not_configured when the mode was never passed to createJwtAuth', async () => {
    const mode = oauthAuthorizationCode({
      clientId: 'a',
      redirectUri: 'https://x/cb',
      scope: 's',
      authorizeUrl: 'https://x/authorize',
      pendingStore: memPending(),
    });
    const e1 = await caught(mode.beginLogin());
    expect(e1.code).toBe('not_configured');
    expect(e1.module).toBe('oauth');
    expect((await caught(mode.completeLogin('https://x/cb?code=1&state=2'))).code).toBe('not_configured');
  });
});

describe('oauthAuthorizationCode.completeLogin', () => {
  it('exchanges the code with the stored verifier at the default token route, stores the pair and flips state', async () => {
    const s = setup();
    const state = params(await s.mode.beginLogin()).get('state') ?? '';
    const verifier = s.pending.current?.verifier ?? '';
    expect(s.auth.getState().status).not.toBe('authenticated');
    await s.auth.ready();
    await s.mode.completeLogin(callback(state));
    expect(s.calls).toHaveLength(1);
    const c = s.calls[0];
    expect(c?.method).toBe('POST');
    expect(c?.url).toBe('https://api.example.com/oauth/token');
    expect(c?.headers.get('Content-Type')).toBe('application/x-www-form-urlencoded');
    expect(c?.headers.has('Authorization')).toBe(false); // public client
    expect(c?.headers.get('X-Device-Id')).toBe('dev-1');
    expect(c?.body).toBe(
      new URLSearchParams({
        grant_type: 'authorization_code',
        code: CODE,
        redirect_uri: 'https://app.example.com/cb',
        client_id: 'app-1',
        code_verifier: verifier,
      }).toString(),
    );
    expect((await s.store.get())?.accessToken).toBe(ACCESS);
    expect((await s.store.get())?.refreshToken).toBe(REFRESH);
    expect(s.auth.getState().status).toBe('authenticated');
    expect(await s.auth.getAccessToken()).toBe(ACCESS);
    expect(s.pending.current).toBeNull();
    expect(s.events.some((e) => e.type === 'login')).toBe(true);
  });

  it('works without a prior ready() and uses a custom tokenUrl', async () => {
    const s = setup(undefined, { tokenUrl: 'https://idp.example.com/custom/token' });
    const state = params(await s.mode.beginLogin()).get('state') ?? '';
    await s.mode.completeLogin(callback(state));
    expect(s.calls[0]?.url).toBe('https://idp.example.com/custom/token');
    expect(s.auth.getState().status).toBe('authenticated');
  });

  it('sends HTTP Basic (raw id:secret) when a clientSecret is given', async () => {
    const s = setup(undefined, { clientSecret: SECRET });
    const state = params(await s.mode.beginLogin()).get('state') ?? '';
    await s.mode.completeLogin(callback(state));
    expect(s.calls[0]?.headers.get('Authorization')).toBe(`Basic ${btoa(`app-1:${SECRET}`)}`);
    expect(s.calls[0]?.body).not.toContain(SECRET);
  });

  it('cookie transport: tokens are not stored, state flips', async () => {
    const s = setup(
      () => json({ access_token: ACCESS, refresh_token: REFRESH, expires_in: 900 }, 200, { 'X-SP-CSRF': 'csrf-1' }),
      { cookie: true },
    );
    const state = params(await s.mode.beginLogin()).get('state') ?? '';
    await s.mode.completeLogin(callback(state));
    expect(s.calls[0]?.credentials).toBe('include');
    const stored = await s.store.get();
    expect(stored?.accessToken).toBeUndefined();
    expect(stored?.refreshToken).toBeUndefined();
    expect(JSON.stringify(stored)).not.toContain(REFRESH);
    expect(s.auth.getState().status).toBe('authenticated');
  });

  it('rejects a state mismatch without a request, and clears the pending record', async () => {
    const s = setup();
    await s.mode.beginLogin();
    const e = await caught(s.mode.completeLogin(callback('not-the-state')));
    expect(e.code).toBe('invalid_state');
    expect(s.calls).toHaveLength(0);
    expect(s.pending.current).toBeNull();
    expect((await s.store.get())?.accessToken).toBeUndefined();
  });

  it('rejects a missing state, a missing code, and no pending login', async () => {
    const s = setup();
    await s.mode.beginLogin();
    expect((await caught(s.mode.completeLogin(`https://app.example.com/cb?code=${CODE}`))).code).toBe('invalid_state');
    expect(s.pending.current).toBeNull();
    // no pending record at all
    expect((await caught(s.mode.completeLogin(callback('whatever')))).code).toBe('invalid_state');
    const state = params(await s.mode.beginLogin()).get('state') ?? '';
    expect((await caught(s.mode.completeLogin(`https://app.example.com/cb?state=${state}`))).code).toBe('invalid_request');
    expect(s.pending.current).toBeNull();
    expect(s.calls).toHaveLength(0);
  });

  it('a state is single-use: replaying the same callback after success is rejected', async () => {
    const s = setup();
    const state = params(await s.mode.beginLogin()).get('state') ?? '';
    const cb = callback(state);
    await s.mode.completeLogin(cb);
    expect(s.pending.current).toBeNull();
    expect((await caught(s.mode.completeLogin(cb))).code).toBe('invalid_state');
    expect(s.calls).toHaveLength(1);
  });

  it('two concurrent completions of the same callback exchange the code once', async () => {
    const s = setup();
    const state = params(await s.mode.beginLogin()).get('state') ?? '';
    const cb = callback(state);
    const results = await Promise.allSettled([s.mode.completeLogin(cb), s.mode.completeLogin(cb)]);
    expect(results.map((r) => r.status).sort()).toEqual(['fulfilled', 'rejected']);
    expect(s.calls).toHaveLength(1);
  });

  it('surfaces error=access_denied as a typed error (code = the error value), clears pending, no request', async () => {
    const s = setup();
    const state = params(await s.mode.beginLogin()).get('state') ?? '';
    const e = await caught(
      s.mode.completeLogin(callback(state, { error: 'access_denied', error_description: 'The user said no' })),
    );
    expect(e.code).toBe('access_denied');
    expect(e.message).toContain('The user said no');
    expect(e.module).toBe('oauth');
    expect(s.pending.current).toBeNull();
    expect(s.calls).toHaveLength(0);
  });

  it('a failed exchange maps the RFC error, clears pending, stores nothing; replay then fails on state', async () => {
    const s = setup(() => json({ error: 'invalid_grant', error_description: 'bad code' }, 400));
    const state = params(await s.mode.beginLogin()).get('state') ?? '';
    const cb = callback(state);
    const e = await caught(s.mode.completeLogin(cb));
    expect(e.code).toBe('invalid_grant');
    expect(e.status).toBe(400);
    expect(s.pending.current).toBeNull();
    expect((await s.store.get())?.accessToken).toBeUndefined();
    expect(s.auth.getState().status).not.toBe('authenticated');
    expect((await caught(s.mode.completeLogin(cb))).code).toBe('invalid_state');
  });

  it('a 404 on the token route is module_disabled', async () => {
    const s = setup(() => new Response('not found', { status: 404 }));
    const state = params(await s.mode.beginLogin()).get('state') ?? '';
    const e = await caught(s.mode.completeLogin(callback(state)));
    expect(e.code).toBe('module_disabled');
    expect(e.module).toBe('oauth');
  });

  it('a 2xx without a token pair is unknown with no body on the error, and nothing is stored', async () => {
    const s2 = setup(() => json({ nope: REFRESH }));
    const state = params(await s2.mode.beginLogin()).get('state') ?? '';
    const e = await caught(s2.mode.completeLogin(callback(state)));
    expect(e.code).toBe('unknown');
    expect(e.body).toBeNull();
    expect(JSON.stringify([e.message, e.body])).not.toContain(REFRESH);
    expect((await s2.store.get())?.accessToken).toBeUndefined();
  });

  it('a throwing function-valued unwrap becomes unknown with a fixed message, pending cleared', async () => {
    const s = setup(undefined, {
      unwrap: () => {
        throw new Error(`boom ${REFRESH}`);
      },
    });
    const state = params(await s.mode.beginLogin()).get('state') ?? '';
    const e = await caught(s.mode.completeLogin(callback(state)));
    expect(e.code).toBe('unknown');
    expect(JSON.stringify([e.message, e.body])).not.toContain(REFRESH);
    expect(s.pending.current).toBeNull();
    expect((await s.store.get())?.accessToken).toBeUndefined();
  });

  it('secrets hygiene: errors, events and state never carry code, verifier, state, secret or tokens', async () => {
    const s = setup(() => json({ error: 'invalid_client', error_description: 'bad client' }, 401), { clientSecret: SECRET });
    const state = params(await s.mode.beginLogin()).get('state') ?? '';
    const verifier = s.pending.current?.verifier ?? '';
    const e = await caught(s.mode.completeLogin(callback(state)));
    expect(e.code).toBe('invalid_client');
    const dump = JSON.stringify([e.message, e.body, e.code, s.events, s.auth.getState()]);
    for (const secret of [SECRET, CODE, verifier, state, REFRESH, ACCESS]) expect(dump).not.toContain(secret);

    const ok = setup(undefined, { clientSecret: SECRET });
    const st = params(await ok.mode.beginLogin()).get('state') ?? '';
    const v = ok.pending.history[0]?.verifier ?? '';
    await ok.mode.completeLogin(callback(st));
    const dump2 = JSON.stringify([ok.events, ok.auth.getState()]);
    for (const secret of [SECRET, CODE, v, st, REFRESH, ACCESS]) expect(dump2).not.toContain(secret);
  });
});

describe('default pending store', () => {
  it('persists through sessionStorage when available and clears it after use', async () => {
    const data = new Map<string, string>();
    const fake = {
      getItem: (k: string) => data.get(k) ?? null,
      setItem: (k: string, v: string) => void data.set(k, v),
      removeItem: (k: string) => void data.delete(k),
    };
    const g = globalThis as Record<string, unknown>;
    const had = Object.getOwnPropertyDescriptor(g, 'sessionStorage');
    Object.defineProperty(g, 'sessionStorage', { value: fake, configurable: true, writable: true });
    try {
      const calls: Call[] = [];
      const mode = oauthAuthorizationCode({
        clientId: 'app-1',
        redirectUri: 'https://app.example.com/cb',
        scope: 's',
        authorizeUrl: 'https://api.example.com/oauth/authorize',
        session: { crossTab: false, storage: memoryStore() },
      });
      createJwtAuth({ baseUrl: 'https://api.example.com', endpoints: {}, mode, fetch: makeFetch(() => tokenOk(), calls) });
      const state = params(await mode.beginLogin()).get('state') ?? '';
      expect(data.size).toBe(1);
      await mode.completeLogin(callback(state));
      expect(data.size).toBe(0);
    } finally {
      if (had) Object.defineProperty(g, 'sessionStorage', had);
      else delete g.sessionStorage;
    }
  });

  it('falls back to memory when sessionStorage is missing or throws', async () => {
    const g = globalThis as Record<string, unknown>;
    const had = Object.getOwnPropertyDescriptor(g, 'sessionStorage');
    const boom = (): never => {
      throw new Error('blocked');
    };
    Object.defineProperty(g, 'sessionStorage', {
      value: { getItem: boom, setItem: boom, removeItem: boom },
      configurable: true,
      writable: true,
    });
    try {
      const calls: Call[] = [];
      const mode = oauthAuthorizationCode({
        clientId: 'app-1',
        redirectUri: 'https://app.example.com/cb',
        scope: 's',
        authorizeUrl: 'https://api.example.com/oauth/authorize',
        session: { crossTab: false, storage: memoryStore() },
      });
      const auth = createJwtAuth({ baseUrl: 'https://api.example.com', endpoints: {}, mode, fetch: makeFetch(() => tokenOk(), calls) });
      const state = params(await mode.beginLogin()).get('state') ?? '';
      await mode.completeLogin(callback(state));
      expect(auth.getState().status).toBe('authenticated');
    } finally {
      if (had) Object.defineProperty(g, 'sessionStorage', had);
      else delete g.sessionStorage;
    }
  });
});

interface OSetup {
  auth: JwtAuth;
  calls: Call[];
}
function osetup(handler: Handler, o: { unwrap?: Unwrap; endpoints?: Record<string, string> } = {}): OSetup {
  const calls: Call[] = [];
  const auth = createJwtAuth({
    baseUrl: 'https://api.example.com',
    endpoints: { ...(o.endpoints ?? {}) },
    mode: userSession({ crossTab: false, storage: memoryStore() }),
    fetch: makeFetch(handler, calls),
    ...(o.unwrap ? { unwrap: o.unwrap } : {}),
  });
  return { auth, calls };
}
const creds = { clientId: 'srv-1', clientSecret: SECRET };

describe('oauth(auth).introspect', () => {
  it('maps RFC 7662 (scope string, exp seconds, client_id, sub, jti)', async () => {
    const s = osetup(() =>
      json({ active: true, scope: 'read write', client_id: 'c1', sub: '42', token_type: 'Bearer', exp: 1900000000, jti: 'j1' }),
    );
    const r = await oauth(s.auth, creds).introspect('tok-1');
    expect(r).toEqual({
      active: true,
      clientId: 'c1',
      userId: '42',
      scopes: ['read', 'write'],
      expiresAt: new Date(1900000000 * 1000),
      tokenId: 'j1',
    });
    const c = s.calls[0];
    expect(c?.method).toBe('POST');
    expect(c?.url).toBe('https://api.example.com/oauth/introspect');
    expect(c?.headers.get('Content-Type')).toBe('application/x-www-form-urlencoded');
    expect(c?.body).toBe('token=tok-1');
    expect(c?.headers.get('Authorization')).toBe(`Basic ${btoa(`srv-1:${SECRET}`)}`);
    expect(c?.headers.has('X-Device-Id')).toBe(false);
  });

  it('maps the legacy camelCase shape (ISO and numeric expiresAt, null)', async () => {
    const base = { active: true, clientId: 'c1', userType: 'user', userId: '42', grantType: 'authorization_code', scopes: ['a', 'b'], claims: {}, tokenId: 'j2' };
    const iso = await oauth(osetup(() => json({ ...base, expiresAt: '2030-01-01T00:00:00.000000Z' })).auth, creds).introspect('t');
    expect(iso).toEqual({ active: true, clientId: 'c1', userId: '42', scopes: ['a', 'b'], expiresAt: new Date('2030-01-01T00:00:00.000Z'), tokenId: 'j2' });
    const nul = await oauth(osetup(() => json({ ...base, expiresAt: null })).auth, creds).introspect('t');
    expect(nul.expiresAt).toBeNull();
  });

  it('inactive is just { active: false } (RFC and legacy)', async () => {
    expect(await oauth(osetup(() => json({ active: false })).auth, creds).introspect('t')).toEqual({ active: false });
    expect(
      await oauth(osetup(() => json({ active: false, clientId: null, scopes: [], claims: [], expiresAt: null })).auth, creds).introspect('t'),
    ).toEqual({ active: false });
  });

  it('an active token without exp has expiresAt null, and without scope has empty scopes', async () => {
    const r = await oauth(osetup(() => json({ active: true, client_id: 'c', scope: '' })).auth, creds).introspect('t');
    expect(r).toEqual({ active: true, clientId: 'c', scopes: [], expiresAt: null });
  });

  it('body auth sends client_id/client_secret as form fields and no Authorization', async () => {
    const s = osetup(() => json({ active: false }));
    await oauth(s.auth, { ...creds, auth: 'body' }).introspect('tok');
    const c = s.calls[0];
    expect(c?.headers.has('Authorization')).toBe(false);
    expect(c?.body).toBe(new URLSearchParams({ token: 'tok', client_id: 'srv-1', client_secret: SECRET }).toString());
  });

  it('uses endpoints.oauthIntrospect when set', async () => {
    const s = osetup(() => json({ active: false }), { endpoints: { oauthIntrospect: '/custom/introspect' } });
    await oauth(s.auth, creds).introspect('t');
    expect(s.calls[0]?.path).toBe('/custom/introspect');
  });

  it('401 invalid_client (WWW-Authenticate) throws with that code', async () => {
    const s = osetup(() =>
      json({ error: 'invalid_client', error_description: 'OAuth client is invalid.' }, 401, { 'WWW-Authenticate': 'Basic realm="oauth"' }),
    );
    const e = await caught(oauth(s.auth, creds).introspect('t'));
    expect(e.code).toBe('invalid_client');
    expect(e.status).toBe(401);
    expect(e.module).toBe('oauth');
    expect(JSON.stringify([e.message, e.body])).not.toContain(SECRET);
  });

  it.each(['invalid_grant', 'invalid_scope', 'unsupported_grant_type', 'invalid_request'])('maps RFC error %s', async (code) => {
    const s = osetup(() => json({ error: code, error_description: 'x' }, 400));
    expect((await caught(oauth(s.auth, creds).introspect('t'))).code).toBe(code);
  });

  it('a 404 is module_disabled (module oauth)', async () => {
    const s = osetup(() => new Response('', { status: 404 }));
    const e = await caught(oauth(s.auth, creds).introspect('t'));
    expect(e.code).toBe('module_disabled');
    expect(e.module).toBe('oauth');
  });

  it('a 2xx that is not an introspection body throws unknown', async () => {
    const s = osetup(() => json({ hello: 'world' }));
    const e = await caught(oauth(s.auth, creds).introspect('t'));
    expect(e.code).toBe('unknown');
    expect(e.body).toBeNull();
  });

  it('a throwing function-valued unwrap becomes unknown with a fixed message', async () => {
    const s = osetup(() => json({ active: true }), {
      unwrap: () => {
        throw new Error(`boom ${SECRET}`);
      },
    });
    const e = await caught(oauth(s.auth, creds).introspect('t'));
    expect(e.code).toBe('unknown');
    expect(JSON.stringify([e.message, e.body])).not.toContain(SECRET);
  });

  it('honours a configured envelope unwrap', async () => {
    const s = osetup(() => json({ success: true, data: { active: true, client_id: 'c' } }), { unwrap: 'envelope' as Unwrap });
    expect((await oauth(s.auth, creds).introspect('t')).clientId).toBe('c');
  });

  it('requires creds: not_configured (module oauth) without a request when omitted', async () => {
    const s = osetup(() => json({ active: false }));
    const e = await caught(oauth(s.auth).introspect('t'));
    expect(e.code).toBe('not_configured');
    expect(e.module).toBe('oauth');
    expect(s.calls).toHaveLength(0);
    expect((await caught(oauth(s.auth).revoke('t'))).code).toBe('not_configured');
  });
});

describe('oauth(auth).revoke', () => {
  it('POSTs token and hint with Basic auth to the default route and resolves void on 200 {}', async () => {
    const s = osetup(() => json([], 200));
    await expect(oauth(s.auth, creds).revoke('tok-9', 'refresh_token')).resolves.toBeUndefined();
    const c = s.calls[0];
    expect(c?.url).toBe('https://api.example.com/oauth/revoke');
    expect(c?.body).toBe('token=tok-9&token_type_hint=refresh_token');
    expect(c?.headers.get('Authorization')).toBe(`Basic ${btoa(`srv-1:${SECRET}`)}`);
  });

  it('omits the hint when not given; body auth puts the credentials in the form', async () => {
    const s = osetup(() => json({}, 200));
    await oauth(s.auth, { ...creds, auth: 'body' }).revoke('tok');
    expect(s.calls[0]?.body).toBe(new URLSearchParams({ token: 'tok', client_id: 'srv-1', client_secret: SECRET }).toString());
  });

  it('401 invalid_client throws invalid_client; 404 is module_disabled', async () => {
    const s = osetup(() => json({ error: 'invalid_client', error_description: 'x' }, 401));
    expect((await caught(oauth(s.auth, creds).revoke('t'))).code).toBe('invalid_client');
    const s2 = osetup(() => new Response('', { status: 404 }));
    expect((await caught(oauth(s2.auth, creds).revoke('t'))).code).toBe('module_disabled');
  });

  it('does not leak the secret or the token through errors or state', async () => {
    const s = osetup(() => json({ error: 'invalid_client', error_description: 'x' }, 401));
    const e = await caught(oauth(s.auth, creds).revoke('tok-leak-check'));
    const dump = JSON.stringify([e.message, e.body, s.auth.getState()]);
    expect(dump).not.toContain(SECRET);
    expect(dump).not.toContain('tok-leak-check');
  });
});
