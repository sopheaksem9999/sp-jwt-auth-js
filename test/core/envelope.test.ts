import { describe, expect, it } from 'vitest';
import { createJwtAuth, userSession } from '../../src/core/create-jwt-auth';
import type { AuthEvent } from '../../src/core/create-jwt-auth';
import { memoryStore } from '../../src/core/stores';
import { SpAuthError, authErrorFromResponse } from '../../src/core/errors';
import { throwIfEnvelopeFailure } from '../../src/core/envelope';

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

const access = jwt({ sub: '7', exp: now() + 900 });
const pair = { access_token: access, refresh_token: 'r1', expires_in: 900, token_type: 'Bearer' };
const failure = { success: false, error_code: 10004, message: 'Invalid OTP code', meta: { request_id: 'r1' } };

function setup(responder: (url: string) => Response, cookie = false) {
  const store = memoryStore();
  const events: AuthEvent[] = [];
  const auth = createJwtAuth({
    baseUrl: 'https://api.example.com/',
    endpoints: { login: '/auth/login', secondFactor: '/auth/2fa', refresh: '/auth/refresh' },
    mode: userSession({ storage: store, crossTab: false, ...(cookie ? { transport: 'cookie' as const } : {}) }),
    fetch: (async (input: RequestInfo | URL) => responder(String(input))) as typeof fetch,
    onEvent: (e) => events.push(e),
  });
  return { auth, store, events };
}

async function rejection(p: Promise<unknown>): Promise<SpAuthError> {
  try {
    await p;
  } catch (e) {
    return e as SpAuthError;
  }
  throw new Error('expected a rejection');
}

describe('throwIfEnvelopeFailure', () => {
  it('throws request_failed with status, message, errorCode and requestId', () => {
    let err: SpAuthError | undefined;
    try {
      throwIfEnvelopeFailure(failure, 'login');
    } catch (e) {
      err = e as SpAuthError;
    }
    expect(err).toBeInstanceOf(SpAuthError);
    expect([err?.status, err?.code, err?.message, err?.errorCode, err?.requestId, err?.module]).toEqual([
      200,
      'request_failed',
      'Invalid OTP code',
      10004,
      'r1',
      'login',
    ]);
  });

  it('accepts a numeric-string error_code, defaults message and requestId', () => {
    try {
      throwIfEnvelopeFailure({ success: false, error_code: '10004' });
      expect.unreachable();
    } catch (e) {
      const err = e as SpAuthError;
      expect([err.errorCode, err.requestId, err.message]).toEqual([10004, null, 'Request failed']);
    }
  });

  it('ignores a non-numeric error_code', () => {
    try {
      throwIfEnvelopeFailure({ success: false, error_code: 'abc', meta: 'x' });
      expect.unreachable();
    } catch (e) {
      expect((e as SpAuthError).errorCode).toBeNull();
    }
  });

  it('returns for arrays, strings, null, success true and flat bodies', () => {
    for (const b of [[], ['x'], 'text', null, undefined, 5, { success: true }, { access_token: 'x' }, { success: 'false' }]) {
      expect(() => throwIfEnvelopeFailure(b)).not.toThrow();
    }
  });

  it('fills errorCode from a non-2xx envelope body', async () => {
    const err = await authErrorFromResponse(json({ success: false, error_code: '10010', message: 'no' }, 400));
    expect(err.errorCode).toBe(10010);
    expect((await authErrorFromResponse(json({ message: 'no' }, 400))).errorCode).toBeNull();
  });
});

describe('login / verifySecondFactor on a 200 failure', () => {
  it.each([
    ['login', (a: ReturnType<typeof setup>['auth']) => a.login({ email: 'a@b.c', password: 'p' })],
    ['verifySecondFactor', (a: ReturnType<typeof setup>['auth']) => a.verifySecondFactor({ kind: '2fa_token', token: 't' }, '123456')],
  ])('%s throws request_failed and leaves the session untouched', async (_n, call) => {
    const { auth, store, events } = setup(() => json(failure));
    await auth.ready();
    events.length = 0;
    const before = auth.getState();
    const err = await rejection(call(auth));
    expect([err.status, err.code, err.message, err.errorCode, err.requestId]).toEqual([200, 'request_failed', 'Invalid OTP code', 10004, 'r1']);
    expect(await store.get()).toBeNull();
    expect(auth.getState().status).toBe(before.status);
    expect(events).toEqual([]);
  });

  it('a failed login leaves an existing session intact', async () => {
    let fail = false;
    const { auth, store, events } = setup(() => (fail ? json(failure) : json(pair)));
    await auth.login({ email: 'a@b.c', password: 'p' });
    const tokens = await store.get();
    const state = auth.getState();
    events.length = 0;
    fail = true;
    await rejection(auth.login({ email: 'a@b.c', password: 'bad' }));
    await rejection(auth.verifySecondFactor({ kind: '2fa_token', token: 't' }, '1'));
    expect(await store.get()).toEqual(tokens);
    expect(auth.getState()).toEqual(state);
    expect(events).toEqual([]);
  });

  it.each([[[]], ['plain text'], [null]])('a non-object body (%j) never throws a TypeError', async (body) => {
    const { auth } = setup(() => json(body));
    const err = await rejection(auth.login({ email: 'a@b.c', password: 'p' }));
    expect(err).toBeInstanceOf(SpAuthError);
    expect(err.code).toBe('unknown');
  });

  it('a 2FA challenge body still returns second_factor_required', async () => {
    const { auth } = setup(() => json({ success: true, requires_2fa: true, '2fa_token': 'tok' }));
    expect(await auth.login({ email: 'a@b.c', password: 'p' })).toEqual({
      status: 'second_factor_required',
      challenge: { kind: '2fa_token', token: 'tok' },
    });
  });

  it('a success:true envelope still signs in', async () => {
    const { auth } = setup(() => json({ success: true, data: pair }), false);
    expect((await auth.login({ email: 'a@b.c', password: 'p' })).status).toBe('authenticated');
  });
});

describe.each([false, true])('refresh on a 200 failure (cookie transport: %s)', (cookie) => {
  async function loggedIn(refreshBody: unknown) {
    const s = setup((url) => (url.endsWith('/auth/refresh') ? json(refreshBody) : json(pair)), cookie);
    await s.auth.login({ email: 'a@b.c', password: 'p' });
    s.events.length = 0;
    return s;
  }

  it('error_code 5: refresh fails, refresh_failed is emitted, the session stays', async () => {
    const { auth, store, events } = await loggedIn({ success: false, error_code: 5, message: 'later' });
    const err = await rejection(auth.refresh());
    expect([err.code, err.errorCode]).toEqual(['request_failed', 5]);
    expect(events.map((e) => e.type)).toEqual(['refresh_failed']);
    expect(auth.getState().status).toBe('authenticated');
    if (!cookie) expect((await store.get())?.refreshToken).toBe('r1');
  });

  it.each([10002, '10010'])('error_code %s ends the session with refresh_rejected', async (code) => {
    const { auth, events } = await loggedIn({ success: false, error_code: code });
    const err = await rejection(auth.refresh());
    expect(err.code).toBe('session_ended');
    expect(events.find((e) => e.type === 'session_ended')).toMatchObject({ reason: 'refresh_rejected' });
    expect(auth.getState().status).toBe('anonymous');
  });
});
