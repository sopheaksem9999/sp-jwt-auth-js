import { describe, expect, it } from 'vitest';
import { createJwtAuth, memoryStore, userSession } from '../../src';
import type { AuthEvent, JwtAuth, TokenStore, Unwrap } from '../../src';
import { SpAuthError } from '../../src';
import { social } from '../../src/social';

function b64url(s: string): string {
  let bin = '';
  for (const b of new TextEncoder().encode(s)) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function jwt(payload: Record<string, unknown>): string {
  return `${b64url(JSON.stringify({ alg: 'none', typ: 'JWT' }))}.${b64url(JSON.stringify(payload))}.sig`;
}
const ACCESS = jwt({ sub: '7', exp: Math.floor(Date.now() / 1000) + 900 });
const REFRESH = 'rt-social-secret-never-in-errors';
const CODE = 'oauth-code-secret-777';
const pairBody = { access_token: ACCESS, refresh_token: REFRESH, token_type: 'Bearer', expires_in: 900 };

const ENDPOINTS = { socialRedirect: '/auth/:provider/redirect', socialCallback: '/auth/:provider/callback' };

function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } });
}

interface Call {
  method: string;
  url: string;
  path: string;
  headers: Headers;
  body: string | undefined;
  credentials: RequestCredentials | undefined;
}
interface Setup {
  auth: JwtAuth;
  store: TokenStore;
  calls: Call[];
  events: AuthEvent[];
}

function setup(
  respond: (c: Call) => Response,
  o: { endpoints?: Record<string, string>; cookie?: boolean; device?: boolean; unwrap?: Unwrap; baseUrl?: string } = {},
): Setup {
  const calls: Call[] = [];
  const f = (async (input: string | URL, init?: RequestInit): Promise<Response> => {
    const c: Call = {
      method: init?.method ?? 'GET',
      url: String(input),
      path: new URL(String(input)).pathname,
      headers: new Headers(init?.headers),
      body: typeof init?.body === 'string' ? init.body : undefined,
      credentials: init?.credentials,
    };
    calls.push(c);
    return respond(c);
  }) as unknown as typeof fetch;
  const store = memoryStore();
  const events: AuthEvent[] = [];
  const auth = createJwtAuth({
    baseUrl: o.baseUrl ?? 'https://api.example.com/api/v2',
    endpoints: o.endpoints ?? ENDPOINTS,
    mode: userSession({ crossTab: false, storage: store, ...(o.cookie ? { transport: 'cookie' as const } : {}) }),
    fetch: f,
    ...(o.unwrap ? { unwrap: o.unwrap } : {}),
    ...(o.device ? { device: { id: 'dev-1', name: 'Laptop' } } : {}),
    onEvent: (e) => events.push(e),
  });
  return { auth, store, calls, events };
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

function deepStrings(v: unknown, seen = new Set<unknown>()): string[] {
  if (typeof v === 'string') return [v];
  if (typeof v !== 'object' || v === null || seen.has(v)) return [];
  seen.add(v);
  const out: string[] = [];
  for (const k of Object.getOwnPropertyNames(v)) out.push(k, ...deepStrings((v as Record<string, unknown>)[k], seen));
  return out;
}

describe('social.redirectUrl', () => {
  it('builds baseUrl + socialRedirect with the provider substituted; no network, no state change', () => {
    const s = setup(() => json({}));
    const before = s.auth.getState();
    expect(social(s.auth).redirectUrl('google')).toBe('https://api.example.com/api/v2/auth/google/redirect');
    expect(s.calls).toHaveLength(0);
    expect(s.auth.getState()).toBe(before);
  });

  it('a trailing slash on baseUrl is handled; absolute endpoints stay absolute', () => {
    const a = setup(() => json({}), { baseUrl: 'https://api.example.com/api/v2/' });
    expect(social(a.auth).redirectUrl('github')).toBe('https://api.example.com/api/v2/auth/github/redirect');
    const b = setup(() => json({}), { endpoints: { socialRedirect: 'https://sso.example.org/login/:provider' } });
    expect(social(b.auth).redirectUrl('github')).toBe('https://sso.example.org/login/github');
  });

  it('hostile providers are encoded and cannot alter the path', () => {
    for (const v of ['a/b', 'a?x=1', 'a#f', 'a/../b', '../../x', 'a b', "a$&b"]) {
      const s = setup(() => json({}));
      const u = new URL(social(s.auth).redirectUrl(v));
      expect(u.pathname).toBe(`/api/v2/auth/${encodeURIComponent(v)}/redirect`);
      expect(u.search).toBe('');
      expect(u.hash).toBe('');
    }
  });

  it('dot-segment or empty providers throw without effect', () => {
    const s = setup(() => json({}));
    for (const v of ['', '.', '..']) expect(() => social(s.auth).redirectUrl(v)).toThrow(SpAuthError);
  });

  it('unset socialRedirect -> not_configured (module social)', () => {
    const s = setup(() => json({}), { endpoints: {} });
    try {
      social(s.auth).redirectUrl('google');
      throw new Error('expected throw');
    } catch (e) {
      expect(e).toBeInstanceOf(SpAuthError);
      expect([(e as SpAuthError).code, (e as SpAuthError).module]).toEqual(['not_configured', 'social']);
    }
  });
});

describe('social.completeFromCallback', () => {
  it('POSTs the params as JSON to the provider callback (encoded), unauthenticated, device headers; stores the pair', async () => {
    const s = setup(() => json(pairBody), { device: true });
    await social(s.auth).completeFromCallback('google', { code: CODE, state: 'st-1' });
    const c = s.calls[0];
    expect(c?.method).toBe('POST');
    expect(c?.path).toBe('/api/v2/auth/google/callback');
    expect(JSON.parse(c?.body ?? '')).toEqual({ code: CODE, state: 'st-1' });
    expect(c?.headers.has('Authorization')).toBe(false);
    expect(c?.headers.get('X-Device-Id')).toBe('dev-1');
    expect(c?.headers.get('X-Device-Name')).toBe('Laptop');
    expect(c?.credentials).toBeUndefined();
    expect(s.auth.getState().status).toBe('authenticated');
    const t = await s.store.get();
    expect(t?.accessToken).toBe(ACCESS);
    expect(t?.refreshToken).toBe(REFRESH);
  });

  it('hostile provider is encoded in the callback path', async () => {
    const s = setup(() => json(pairBody));
    await social(s.auth).completeFromCallback('a/../b?x#y', { code: 'c' });
    const u = new URL(s.calls[0]?.url ?? '');
    expect(u.pathname).toBe(`/api/v2/auth/${encodeURIComponent('a/../b?x#y')}/callback`);
    expect(u.search).toBe('');
  });

  it('cookie transport: credentials include, CSRF from the response, no tokens stored', async () => {
    const s = setup(() => json(pairBody, 200, { 'X-SP-CSRF': 'csrf-from-social' }), { cookie: true, device: true });
    await social(s.auth).completeFromCallback('github', { code: CODE });
    expect(s.calls[0]?.credentials).toBe('include');
    expect(s.calls[0]?.headers.get('X-Device-Id')).toBe('dev-1');
    const t = await s.store.get();
    expect(t?.csrf).toBe('csrf-from-social');
    expect(t).not.toHaveProperty('accessToken');
    expect(t).not.toHaveProperty('refreshToken');
    expect(s.auth.getState().status).toBe('authenticated');
    expect(deepStrings([t, s.auth.getState(), s.events]).join('|')).not.toContain(REFRESH);
  });

  it('unwraps an enveloped pair via the configured unwrap', async () => {
    const s = setup(() => json({ data: pairBody }), { unwrap: 'laravel' });
    await social(s.auth).completeFromCallback('google', { code: CODE });
    expect(s.auth.getState().status).toBe('authenticated');
  });

  it('failures store nothing and leak no secret (HTTP error, no pair, throwing unwrap)', async () => {
    const mk = (respond: () => Response, unwrap?: Unwrap): Setup => setup(respond, unwrap ? { unwrap } : {});
    const cases: Setup[] = [
      mk(() => json({ message: 'denied' }, 422)),
      mk(() => json({ ok: true })),
      mk(() => json({ ok: true }), () => {
        throw new Error(`raw ${CODE}`);
      }),
    ];
    for (const s of cases) {
      const e = await caught(social(s.auth).completeFromCallback('google', { code: CODE, state: 's' }));
      expect(e.module).toBe('social');
      expect(await s.store.get()).toBeNull();
      expect(s.auth.getState().status).not.toBe('authenticated');
      const surface = [`${e.message}|${e.name}`, ...deepStrings(e.cause), ...deepStrings(s.events)].join('|');
      expect(surface).not.toContain(CODE);
    }
  });

  it('a throwing function unwrap -> unknown (module social)', async () => {
    const s = setup(() => json({ x: 1 }), {
      unwrap: () => {
        throw new Error('raw');
      },
    });
    const e = await caught(social(s.auth).completeFromCallback('google', { code: 'c' }));
    expect([e.code, e.module]).toEqual(['unknown', 'social']);
  });

  it('unset socialCallback -> not_configured (module social), no request', async () => {
    const s = setup(() => json(pairBody), { endpoints: {} });
    const e = await caught(social(s.auth).completeFromCallback('google', { code: 'c' }));
    expect([e.code, e.module]).toEqual(['not_configured', 'social']);
    expect(s.calls).toHaveLength(0);
  });
});
