import { describe, expect, it } from 'vitest';
import { createJwtAuth, memoryStore, userSession } from '../../src';
import type { AuthEvent, JwtAuth, TokenStore, Unwrap } from '../../src';
import { SpAuthError } from '../../src';
import { account } from '../../src/account';

function b64url(s: string): string {
  let bin = '';
  for (const b of new TextEncoder().encode(s)) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function jwt(payload: Record<string, unknown>): string {
  return `${b64url(JSON.stringify({ alg: 'none', typ: 'JWT' }))}.${b64url(JSON.stringify(payload))}.sig`;
}
const ACCESS = jwt({ sub: '7', exp: Math.floor(Date.now() / 1000) + 900 });
const REFRESH = 'rt-account-secret-never-in-errors';
const PASSWORD = 'Sup3r-Secret-Passw0rd!';
const RESET_TOKEN = 'reset-token-abc-123';

const ENDPOINTS = {
  forgotPassword: '/auth/forgot-password',
  resetPassword: '/auth/reset-password',
  resendVerification: '/auth/resend-email-verification',
  verifyEmail: '/auth/verify-email',
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

interface Call {
  method: string;
  path: string;
  headers: Headers;
  body: string | undefined;
}
interface Setup {
  auth: JwtAuth;
  store: TokenStore;
  calls: Call[];
  events: AuthEvent[];
}

async function setup(
  respond: (c: Call) => Response,
  o: { endpoints?: Record<string, string>; signedIn?: boolean; unwrap?: Unwrap } = {},
): Promise<Setup> {
  const calls: Call[] = [];
  const f = (async (input: string | URL, init?: RequestInit): Promise<Response> => {
    const c: Call = {
      method: init?.method ?? 'GET',
      path: new URL(String(input)).pathname,
      headers: new Headers(init?.headers),
      body: typeof init?.body === 'string' ? init.body : undefined,
    };
    calls.push(c);
    return respond(c);
  }) as unknown as typeof fetch;
  const store = memoryStore();
  if (o.signedIn !== false) await store.set({ accessToken: ACCESS, refreshToken: REFRESH });
  const events: AuthEvent[] = [];
  const auth = createJwtAuth({
    baseUrl: 'https://api.example.com',
    endpoints: o.endpoints ?? ENDPOINTS,
    mode: userSession({ crossTab: false, storage: store }),
    fetch: f,
    ...(o.unwrap ? { unwrap: o.unwrap } : {}),
    onEvent: (e) => events.push(e),
  });
  await auth.ready();
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

const reset = { token: RESET_TOKEN, email: 'a@example.com', password: PASSWORD, password_confirmation: PASSWORD };

describe('account.forgotPassword', () => {
  it('POSTs exactly { email } unauthenticated and returns the unwrapped body', async () => {
    const s = await setup(() => json({ data: { message: 'sent' } }), { unwrap: 'laravel' });
    expect(await account(s.auth).forgotPassword({ email: 'a@example.com' })).toEqual({ message: 'sent' });
    expect(s.calls[0]?.method).toBe('POST');
    expect(s.calls[0]?.path).toBe('/auth/forgot-password');
    expect(JSON.parse(s.calls[0]?.body ?? '')).toEqual({ email: 'a@example.com' });
    expect(s.calls[0]?.headers.has('Authorization')).toBe(false);
    expect(s.auth.getState().status).toBe('authenticated'); // forgot does not touch the session
  });

  it('an empty 200/204 body is fine with the default unwrap', async () => {
    const s = await setup(() => new Response(null, { status: 204 }));
    expect(await account(s.auth).forgotPassword({ email: 'a@example.com' })).toBeNull();
  });
});

describe('account.resetPassword', () => {
  it('POSTs the exact body, unauthenticated; success clears the stored session', async () => {
    const s = await setup(() => json({ message: 'Password reset' }));
    expect(await account(s.auth).resetPassword(reset)).toEqual({ message: 'Password reset' });
    expect(s.calls[0]?.path).toBe('/auth/reset-password');
    expect(JSON.parse(s.calls[0]?.body ?? '')).toEqual(reset);
    expect(s.calls[0]?.headers.has('Authorization')).toBe(false);
    expect(s.auth.getState().status).toBe('anonymous');
    expect(await s.store.get()).toBeNull();
  });

  it('failure (422) keeps the session', async () => {
    const s = await setup(() => json({ message: 'Invalid token', errors: { token: ['bad'] } }, 422));
    const e = await caught(account(s.auth).resetPassword(reset));
    expect(e.module).toBe('account');
    expect(s.auth.getState().status).toBe('authenticated');
    expect((await s.store.get())?.accessToken).toBe(ACCESS);
  });

  it('an unwrap failure after a 2xx does not clear the session', async () => {
    const s = await setup(() => json({ x: 1 }), {
      unwrap: () => {
        throw new Error('boom');
      },
    });
    const e = await caught(account(s.auth).resetPassword(reset));
    expect(e.code).toBe('unknown');
    expect(s.auth.getState().status).toBe('authenticated');
  });
});

describe('account.resendVerification / verifyEmail', () => {
  it('resendVerification sends the bearer when a token is held, and works without one', async () => {
    const a = await setup(() => json({ message: 'sent' }));
    expect(await account(a.auth).resendVerification()).toEqual({ message: 'sent' });
    expect(a.calls[0]?.method).toBe('POST');
    expect(a.calls[0]?.path).toBe('/auth/resend-email-verification');
    expect(a.calls[0]?.headers.get('Authorization')).toBe(`Bearer ${ACCESS}`);
    expect(a.calls[0]?.body).toBeUndefined();
    const b = await setup(() => json({ message: 'sent' }), { signedIn: false });
    await account(b.auth).resendVerification();
    expect(b.calls).toHaveLength(1);
    expect(b.calls[0]?.headers.has('Authorization')).toBe(false);
  });

  it('verifyEmail POSTs the params as the body, unauthenticated, returns the unwrapped body', async () => {
    const s = await setup(() => json({ verified: true }));
    const params = { id: '7', hash: 'h', expires: '123', signature: 'sig' };
    expect(await account(s.auth).verifyEmail(params)).toEqual({ verified: true });
    expect(s.calls[0]?.method).toBe('POST');
    expect(s.calls[0]?.path).toBe('/auth/verify-email');
    expect(JSON.parse(s.calls[0]?.body ?? '')).toEqual(params);
    expect(s.calls[0]?.headers.has('Authorization')).toBe(false);
  });
});

describe('account: guarded unwrap and not_configured', () => {
  it('a throwing function unwrap -> unknown (module account), fixed message, no raw error', async () => {
    for (const run of [
      (a: ReturnType<typeof account>) => a.forgotPassword({ email: 'a@example.com' }),
      (a: ReturnType<typeof account>) => a.resendVerification(),
      (a: ReturnType<typeof account>) => a.verifyEmail({ id: '1' }),
    ]) {
      const s = await setup(() => json({ k: 'leak-body-value' }), {
        unwrap: () => {
          throw new Error('raw failure leak-body-value');
        },
      });
      const e = await caught(run(account(s.auth)));
      expect([e.code, e.module]).toEqual(['unknown', 'account']);
      expect(deepStrings(e).join('|')).not.toContain('leak-body-value');
    }
  });

  it('each unset endpoint throws not_configured (module account) and sends nothing', async () => {
    const cases: [string, (a: ReturnType<typeof account>) => Promise<unknown>][] = [
      ['forgotPassword', (a) => a.forgotPassword({ email: 'a@b.c' })],
      ['resetPassword', (a) => a.resetPassword(reset)],
      ['resendVerification', (a) => a.resendVerification()],
      ['verifyEmail', (a) => a.verifyEmail({})],
    ];
    for (const [name, run] of cases) {
      const s = await setup(() => json({}), { endpoints: {} });
      const e = await caught(run(account(s.auth)));
      expect([name, e.code, e.module]).toEqual([name, 'not_configured', 'account']);
      expect(s.calls).toHaveLength(0);
      expect(s.auth.getState().status).toBe('authenticated');
    }
  });
});

describe('account: secrets', () => {
  it('passwords and reset tokens never appear in errors (message, cause chain), events or state', async () => {
    for (const status of [422, 429, 500]) {
      const s = await setup(() => json({ message: 'nope' }, status));
      const e = await caught(account(s.auth).resetPassword(reset));
      const surface = [`${e.message}|${e.name}`, ...deepStrings(e.cause), ...deepStrings([s.events, s.auth.getState()])].join('|');
      for (const secret of [PASSWORD, RESET_TOKEN, REFRESH, ACCESS]) expect(surface).not.toContain(secret);
    }
    const u = await setup(() => json({}), {
      unwrap: () => {
        throw new Error(`failed with ${PASSWORD}`);
      },
    });
    const e = await caught(account(u.auth).resetPassword(reset));
    expect(deepStrings(e).join('|')).not.toContain(PASSWORD);
    expect(deepStrings([u.events]).join('|')).not.toContain(PASSWORD);
  });
});
