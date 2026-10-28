import { describe, expect, it } from 'vitest';
import { createJwtAuth, memoryStore, userSession } from '../../src';
import type { AuthEvent, JwtAuth, TokenStore, Unwrap } from '../../src';
import { SpAuthError } from '../../src';
import { otp } from '../../src/otp';

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
const REFRESH = 'rt-otp-secret-never-in-errors';
const CODE = '918273';

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

interface Setup {
  auth: JwtAuth;
  store: TokenStore;
  calls: Call[];
  events: AuthEvent[];
}

function setup(
  handler: Handler,
  o: { cookie?: boolean; endpoints?: Record<string, string>; device?: boolean; unwrap?: Unwrap } = {},
): Setup {
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
  const store = memoryStore();
  const events: AuthEvent[] = [];
  const auth = createJwtAuth({
    baseUrl: 'https://api.example.com',
    endpoints: { ...(o.endpoints ?? {}) },
    mode: userSession({ crossTab: false, storage: store, ...(o.cookie ? { transport: 'cookie' as const } : {}) }),
    fetch: f,
    ...(o.unwrap ? { unwrap: o.unwrap } : {}),
    onEvent: (e) => events.push(e),
    ...(o.device ? { device: { id: 'dev-1', name: 'Laptop' } } : {}),
  });
  return { auth, store, calls, events };
}

const sent = { otp_id: 'o-1', destination_masked: 'a***@example.com', expires_in: 300 };
const req = { destination: 'a@example.com', channel: 'email' as const, purpose: 'login' };

async function caught(p: Promise<unknown>): Promise<SpAuthError> {
  try {
    await p;
  } catch (e) {
    expect(e).toBeInstanceOf(SpAuthError);
    return e as SpAuthError;
  }
  throw new Error('expected rejection');
}

describe('otp request / resend / resendByDestination', () => {
  it('202 is success and returns the sent descriptor; POSTs the default /otp routes unauthenticated', async () => {
    const s = setup(() => json(sent, 202), { device: true });
    const o = otp(s.auth);
    expect(await o.request({ ...req, requested_type: 'user' })).toEqual(sent);
    expect(await o.resend({ otp_id: 'o-1', destination: req.destination, channel: req.channel })).toEqual(sent);
    expect(await o.resendByDestination(req)).toEqual(sent);
    expect(s.calls.map((c) => `${c.method} ${c.path}`)).toEqual([
      'POST /otp/request',
      'POST /otp/resend',
      'POST /otp/resend-by-destination',
    ]);
    expect(JSON.parse(s.calls[0]?.body ?? '')).toEqual({ ...req, requested_type: 'user' });
    for (const c of s.calls) {
      expect(c.headers.has('Authorization')).toBe(false);
      expect(c.headers.has('X-Device-Id')).toBe(false);
      expect(c.headers.has('X-Device-Name')).toBe(false);
    }
  });

  it('uses endpoints.otp when set, and parses a { success, data } shape', async () => {
    const s = setup(() => json({ success: true, data: sent }, 202), { endpoints: { otp: '/auth/otp' } });
    expect(await otp(s.auth).request(req)).toEqual(sent);
    expect(s.calls[0]?.path).toBe('/auth/otp/request');
  });

  it('a 2xx without otp_id throws unknown (module otp)', async () => {
    const s = setup(() => json({ ok: true }, 202));
    const e = await caught(otp(s.auth).request(req));
    expect(e.code).toBe('unknown');
    expect(e.module).toBe('otp');
  });

  it('422 -> invalid_code', async () => {
    const s = setup(() => json({ message: 'bad destination' }, 422));
    const e = await caught(otp(s.auth).request(req));
    expect(e.code).toBe('invalid_code');
    expect(e.module).toBe('otp');
  });

  it('429 -> rate_limited with retryAfter (seconds)', async () => {
    const s = setup(() => json({ message: 'slow down' }, 429, { 'Retry-After': '42' }));
    const e = await caught(otp(s.auth).resend({ otp_id: 'o-1', destination: req.destination, channel: req.channel }));
    expect(e.code).toBe('rate_limited');
    expect(e.retryAfter).toBe(42);
  });

  it('429 -> rate_limited with retryAfter (HTTP-date)', async () => {
    const date = new Date(Date.now() + 30_000).toUTCString();
    const s = setup(() => json({ message: 'slow down' }, 429, { 'Retry-After': date }));
    const e = await caught(otp(s.auth).resendByDestination(req));
    expect(e.code).toBe('rate_limited');
    expect(e.retryAfter).toBeGreaterThanOrEqual(28);
    expect(e.retryAfter).toBeLessThanOrEqual(31);
  });

  it('502 -> delivery_failed', async () => {
    const s = setup(() => json({ message: 'provider down' }, 502));
    expect((await caught(otp(s.auth).request(req))).code).toBe('delivery_failed');
  });

  it('404 on a route -> module_disabled with module otp', async () => {
    const s = setup(() => json({ message: 'Not Found' }, 404));
    for (const p of [otp(s.auth).request(req), otp(s.auth).resendByDestination(req)]) {
      const e = await caught(p);
      expect(e.code).toBe('module_disabled');
      expect(e.module).toBe('otp');
    }
  });
});

describe('otp unwrap handling', () => {
  it('a throwing function unwrap on an empty or null 202 body gives unknown, not a TypeError', async () => {
    const fn: Unwrap = (b) => (b as { payload: unknown }).payload;
    for (const body of ['', 'null']) {
      const s = setup(() => new Response(body, { status: 202 }), { unwrap: fn });
      const o = otp(s.auth);
      for (const p of [
        o.request(req),
        o.resend({ otp_id: 'o-1', destination: req.destination, channel: req.channel }),
        o.resendByDestination(req),
      ]) {
        const e = await caught(p);
        expect(e.code).toBe('unknown');
        expect(e.module).toBe('otp');
        expect(e.message).not.toContain('null');
      }
    }
  });

  it('a custom unwrap function works for request, resend and resendByDestination', async () => {
    const s = setup(() => json({ payload: sent }, 202), {
      unwrap: (b) => (b as { payload: unknown }).payload,
    });
    const o = otp(s.auth);
    expect(await o.request(req)).toEqual(sent);
    expect(await o.resend({ otp_id: 'o-1', destination: req.destination, channel: req.channel })).toEqual(sent);
    expect(await o.resendByDestination(req)).toEqual(sent);
  });

  it("configured 'laravel' and 'sp-laravel-api' clients parse OtpSent", async () => {
    const a = setup(() => json({ data: sent }, 202), { unwrap: 'laravel' });
    expect(await otp(a.auth).request(req)).toEqual(sent);
    const b = setup(() => json({ success: true, error_code: null, data: sent, meta: {} }, 202), { unwrap: 'sp-laravel-api' });
    expect(await otp(b.auth).request(req)).toEqual(sent);
  });

  it('a 202 with no otp_id anywhere throws unknown without echoing the body', async () => {
    const s = setup(() => json({ payload: { secret: 'body-secret-xyz' } }, 202), { unwrap: (b) => (b as { payload: unknown }).payload });
    const e = await caught(otp(s.auth).request(req));
    expect(e.code).toBe('unknown');
    expect(e.message).not.toContain('body-secret-xyz');
  });
});

const pairBody = { token_type: 'Bearer', access_token: ACCESS, refresh_token: REFRESH, expires_in: 900 };

describe('otp verify', () => {
  it('stores the pair (body transport), flips state to authenticated, sends device headers, no bearer', async () => {
    const s = setup(() => json(pairBody), { device: true });
    expect(await otp(s.auth).verify({ otp_id: 'o-1', code: CODE })).toBeUndefined();
    expect(s.calls[0]?.path).toBe('/otp/verify');
    expect(JSON.parse(s.calls[0]?.body ?? '')).toEqual({ otp_id: 'o-1', code: CODE });
    expect(s.calls[0]?.headers.get('X-Device-Id')).toBe('dev-1');
    expect(s.calls[0]?.headers.get('X-Device-Name')).toBe('Laptop');
    expect(s.calls[0]?.headers.has('Authorization')).toBe(false);
    expect(s.calls[0]?.credentials).toBeUndefined();
    expect(s.auth.getState().status).toBe('authenticated');
    const t = await s.store.get();
    expect(t?.accessToken).toBe(ACCESS);
    expect(t?.refreshToken).toBe(REFRESH);
  });

  it('cookie transport: credentials include, CSRF read from the response, no tokens in the store', async () => {
    const s = setup(() => json(pairBody, 200, { 'X-SP-CSRF': 'csrf-from-verify' }), { cookie: true, device: true });
    await otp(s.auth).verify({ otp_id: 'o-1', code: CODE, destination: 'a@example.com', channel: 'email' });
    expect(s.calls[0]?.credentials).toBe('include');
    expect(s.calls[0]?.headers.get('X-Device-Id')).toBe('dev-1');
    expect(s.auth.getState().status).toBe('authenticated');
    const t = await s.store.get();
    expect(t?.csrf).toBe('csrf-from-verify');
    expect(t).not.toHaveProperty('accessToken');
    expect(t).not.toHaveProperty('refreshToken');
    expect(JSON.stringify([t, s.auth.getState(), s.events])).not.toContain(REFRESH);
  });

  it('unwraps an enveloped pair', async () => {
    const s = setup(() => json({ data: { ...pairBody, user: { id: 7 } } }));
    await otp(s.auth).verify({ otp_id: 'o-1', code: CODE });
    expect(s.auth.getState().status).toBe('authenticated');
  });

  it('failure leaves state and store unchanged and leaks no secret', async () => {
    const s = setup(() => json({ message: 'The code is invalid' }, 422));
    const before = await s.store.get();
    const e = await caught(otp(s.auth).verify({ otp_id: 'o-1', code: CODE }));
    expect(e.code).toBe('invalid_code');
    expect(e.module).toBe('otp');
    expect(await s.store.get()).toEqual(before);
    expect(s.auth.getState().status).not.toBe('authenticated');
    expect(e.message).not.toContain(CODE);
    expect(JSON.stringify(s.events)).not.toContain(CODE);
  });

  it('a 2xx with no token pair stores nothing', async () => {
    const s = setup(() => json({ ok: true }));
    const before = await s.store.get();
    await caught(otp(s.auth).verify({ otp_id: 'o-1', code: CODE }));
    expect(await s.store.get()).toEqual(before);
    expect(s.auth.getState().status).not.toBe('authenticated');
  });

  it('429 and 404 map the same way', async () => {
    const a = setup(() => json({}, 429, { 'Retry-After': '7' }));
    const e1 = await caught(otp(a.auth).verify({ otp_id: 'o-1', code: CODE }));
    expect([e1.code, e1.retryAfter]).toEqual(['rate_limited', 7]);
    const b = setup(() => json({}, 404));
    const e2 = await caught(otp(b.auth).verify({ otp_id: 'o-1', code: CODE }));
    expect([e2.code, e2.module]).toEqual(['module_disabled', 'otp']);
  });
});

describe('otp on a 200 { success: false }', () => {
  const failure = { success: false, error_code: '10004', message: 'Invalid OTP code', meta: { request_id: 'rq-1' } };
  const bodies = { request: { destination: 'a@example.com', channel: 'email', purpose: 'login' }, resend: { otp_id: 'o-1', destination: 'a@example.com', channel: 'email' }, resendByDestination: { destination: 'a@example.com', channel: 'email', purpose: 'login' }, verify: { otp_id: 'o-1', code: CODE } } as const;

  it.each(Object.keys(bodies) as (keyof typeof bodies)[])('%s throws request_failed and changes nothing', async (name) => {
    const s = setup(() => json(failure));
    await s.auth.ready();
    s.events.length = 0;
    const before = s.auth.getState();
    let err: SpAuthError | undefined;
    try {
      await (otp(s.auth)[name] as (b: unknown) => Promise<unknown>)(bodies[name]);
    } catch (e) {
      err = e as SpAuthError;
    }
    expect([err?.status, err?.code, err?.message, err?.errorCode, err?.requestId, err?.module]).toEqual([200, 'request_failed', 'Invalid OTP code', 10004, 'rq-1', 'otp']);
    expect(await s.store.get()).toBeNull();
    expect(s.auth.getState()).toEqual(before);
    expect(s.events).toEqual([]);
  });

  it('verify leaves an existing session intact', async () => {
    let fail = false;
    const s = setup(() => (fail ? json(failure) : json({ access_token: ACCESS, refresh_token: REFRESH, expires_in: 900, token_type: 'Bearer' })));
    await otp(s.auth).verify(bodies.verify);
    const tokens = await s.store.get();
    s.events.length = 0;
    fail = true;
    await expect(otp(s.auth).verify(bodies.verify)).rejects.toMatchObject({ code: 'request_failed' });
    expect(await s.store.get()).toEqual(tokens);
    expect(s.events).toEqual([]);
  });
});
