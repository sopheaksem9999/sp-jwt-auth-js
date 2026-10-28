import { describe, expect, it } from 'vitest';
import { createJwtAuth, memoryStore, userSession } from '../../src';
import type { Challenge, JwtAuth, Unwrap } from '../../src';
import { SpAuthError } from '../../src';
import { mfa } from '../../src/mfa';

interface Call {
  method: string;
  path: string;
  headers: Headers;
  body: string | undefined;
}

function setup(
  respond: () => Response,
  endpoints: Record<string, string> = { secondFactorResend: '/auth/login/2fa/resend' },
  unwrap?: Unwrap,
): { auth: JwtAuth; calls: Call[] } {
  const calls: Call[] = [];
  const f = (async (input: string | URL, init?: RequestInit): Promise<Response> => {
    calls.push({
      method: init?.method ?? 'GET',
      path: new URL(String(input)).pathname,
      headers: new Headers(init?.headers),
      body: typeof init?.body === 'string' ? init.body : undefined,
    });
    return respond();
  }) as unknown as typeof fetch;
  const auth = createJwtAuth({
    baseUrl: 'https://api.example.com',
    endpoints,
    mode: userSession({ crossTab: false, storage: memoryStore() }),
    fetch: f,
    ...(unwrap ? { unwrap } : {}),
  });
  return { auth, calls };
}

const ok = (body: unknown = { message: 'sent' }): Response =>
  new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } });

describe('mfa.resend', () => {
  it('2fa_token challenge: body { "2fa_token": token }, unauthenticated, returns the body', async () => {
    const s = setup(() => ok({ message: 'sent', expires_in: 300 }));
    const c: Challenge = { kind: '2fa_token', token: 'tok-1' };
    expect(await mfa(s.auth).resend(c)).toEqual({ message: 'sent', expires_in: 300 });
    expect(s.calls).toHaveLength(1);
    expect(s.calls[0]?.method).toBe('POST');
    expect(s.calls[0]?.path).toBe('/auth/login/2fa/resend');
    expect(JSON.parse(s.calls[0]?.body ?? '')).toEqual({ '2fa_token': 'tok-1' });
    expect(s.calls[0]?.headers.has('Authorization')).toBe(false);
  });

  it('challenge_id challenge: body { challenge_id: token }', async () => {
    const s = setup(() => ok());
    await mfa(s.auth).resend({ kind: 'challenge_id', token: 'ch-9' });
    expect(JSON.parse(s.calls[0]?.body ?? '')).toEqual({ challenge_id: 'ch-9' });
  });

  it('returns the body unwrapped per the configured unwrap (laravel, sp-laravel-api, function)', async () => {
    const c: Challenge = { kind: 'challenge_id', token: 'ch-1' };
    const ep = { secondFactorResend: '/r' };
    const a = setup(() => ok({ data: { sent: 1 } }), ep, 'laravel');
    expect(await mfa(a.auth).resend(c)).toEqual({ sent: 1 });
    const b = setup(() => ok({ success: true, data: { sent: 2 }, meta: {} }), ep, 'sp-laravel-api');
    expect(await mfa(b.auth).resend(c)).toEqual({ sent: 2 });
    const f = setup(() => ok({ payload: { sent: 3 } }), ep, (x) => (x as { payload: unknown }).payload);
    expect(await mfa(f.auth).resend(c)).toEqual({ sent: 3 });
  });

  it('a function unwrap that throws on an empty or null body gives unknown (module mfa)', async () => {
    for (const body of ['', 'null']) {
      const s = setup(() => new Response(body, { status: 200 }), { secondFactorResend: '/r' }, (b) => (b as { payload: unknown }).payload);
      let err: unknown;
      try {
        await mfa(s.auth).resend({ kind: 'challenge_id', token: 'ch-1' });
      } catch (e) {
        err = e;
      }
      expect(err).toBeInstanceOf(SpAuthError);
      expect((err as SpAuthError).code).toBe('unknown');
      expect((err as SpAuthError).module).toBe('mfa');
      expect((err as SpAuthError).message).not.toContain('null');
    }
  });

  it('unset endpoints.secondFactorResend -> not_configured (module mfa), no request', async () => {
    const s = setup(() => ok(), {});
    let err: unknown;
    try {
      await mfa(s.auth).resend({ kind: 'challenge_id', token: 'x' });
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(SpAuthError);
    expect((err as SpAuthError).code).toBe('not_configured');
    expect((err as SpAuthError).module).toBe('mfa');
    expect(s.calls).toHaveLength(0);
  });

  it('maps 429, 422 and 502; the challenge token is not in the error message', async () => {
    for (const [status, code] of [[429, 'rate_limited'], [422, 'invalid_code'], [502, 'delivery_failed']] as const) {
      const s = setup(() => new Response(JSON.stringify({ message: 'nope' }), { status, headers: { 'Retry-After': '5' } }));
      let err: unknown;
      try {
        await mfa(s.auth).resend({ kind: '2fa_token', token: 'secret-challenge-token' });
      } catch (e) {
        err = e;
      }
      const e = err as SpAuthError;
      expect(e.code).toBe(code);
      expect(e.module).toBe('mfa');
      expect(e.message).not.toContain('secret-challenge-token');
    }
  });
});

describe('mfa on a 200 { success: false }', () => {
  it('resend rejects with request_failed', async () => {
    const s = setup(() => ok({ success: false, error_code: 10004, message: 'Too soon', meta: { request_id: 'rq-9' } }));
    await expect(mfa(s.auth).resend({ kind: '2fa_token', token: 't' })).rejects.toMatchObject({
      status: 200,
      code: 'request_failed',
      message: 'Too soon',
      errorCode: 10004,
      requestId: 'rq-9',
      module: 'mfa',
    });
  });

  it('resend still resolves a success:true body', async () => {
    const s = setup(() => ok({ success: true, message: 'sent' }));
    expect(await mfa(s.auth).resend({ kind: '2fa_token', token: 't' })).toEqual({ success: true, message: 'sent' });
  });
});
