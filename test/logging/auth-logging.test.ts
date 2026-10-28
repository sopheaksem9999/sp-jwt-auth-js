import { afterEach, describe, expect, it, vi } from 'vitest';
import { createJwtAuth, memoryStore, userSession } from '../../src';
import type { AuthLogEntry, JwtAuth, JwtAuthOptions } from '../../src';
import { createAuthLogger } from '../../src/logging';
import { mfa } from '../../src/mfa';
import { otp } from '../../src/otp';
import { social } from '../../src/social';

function b64url(s: string): string {
  let bin = '';
  for (const b of new TextEncoder().encode(s)) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
const access = `${b64url('{"alg":"none"}')}.${b64url(JSON.stringify({ sub: '7', exp: Math.floor(Date.now() / 1000) + 900 }))}.sig`;
const pair = { access_token: access, refresh_token: 'rt-secret-1', expires_in: 900, token_type: 'Bearer' };

const json = (body: unknown, status = 200, headers: Record<string, string> = {}): Response =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } });

const ALLOWED_KEYS = ['attempt', 'code', 'durationMs', 'errorCode', 'method', 'path', 'requestId', 'status'];
const ENDPOINTS = {
  login: '/auth/login',
  secondFactor: '/auth/login/2fa',
  secondFactorResend: '/auth/login/2fa/resend',
  whoami: '/auth/me',
  otp: '/otp',
  socialCallback: '/auth/:provider/callback',
};

function setup(
  responder: (url: URL, init: RequestInit | undefined) => Response | Promise<Response>,
  extra: Partial<JwtAuthOptions> = {},
): { auth: JwtAuth; entries: AuthLogEntry[] } {
  const entries: AuthLogEntry[] = [];
  const f = (async (input: string | URL, init?: RequestInit) => responder(new URL(String(input)), init)) as unknown as typeof fetch;
  const auth = createJwtAuth({
    baseUrl: 'https://api.example.com/api',
    endpoints: ENDPOINTS,
    mode: userSession({ crossTab: false, storage: memoryStore() }),
    fetch: f,
    logger: createAuthLogger({ sink: (e) => entries.push(e) }),
    logRequests: true,
    ...extra,
  });
  return { auth, entries };
}

describe('request logging', () => {
  it('no entry without logger and logRequests', async () => {
    const seen: AuthLogEntry[] = [];
    for (const extra of [{ logRequests: false }, { logRequests: undefined }] as Partial<JwtAuthOptions>[]) {
      const { auth } = setup(() => json({ token: pair }), { logger: createAuthLogger({ sink: (e) => seen.push(e) }), ...extra });
      await auth.login({ email: 'ada@example.com', password: 'p' });
    }
    const noLogger = setup(() => json({ token: pair }), { logger: undefined });
    await noLogger.auth.login({ email: 'ada@example.com', password: 'p' });
    expect(seen).toEqual([]);
    expect(noLogger.entries).toEqual([]);
  });

  it('login, refresh, revoke, whoami, second factor, OTP, MFA and social calls each produce one entry per attempt', async () => {
    const responder = (url: URL): Response => {
      if (url.pathname.endsWith('/otp/request') || url.pathname.endsWith('/otp/resend')) {
        return json({ otp_id: 'o1', destination_masked: 'a***@example.com', expires_in: 300 }, 202);
      }
      if (url.pathname.endsWith('/auth/me')) return json({ id: 7 });
      if (url.pathname.endsWith('/revoke')) return new Response(null, { status: 204 });
      return json({ token: pair, message: 'ok' });
    };
    const table: [string, string, (a: JwtAuth) => Promise<unknown>][] = [
      ['POST', '/api/auth/login', (a) => a.login({ email: 'ada@example.com', password: 'p' })],
      ['POST', '/api/auth/login/2fa', (a) => a.verifySecondFactor({ kind: '2fa_token', token: 't' }, '123456')],
      ['POST', '/api/auth/token/refresh', async (a) => {
        await a.login({ email: 'ada@example.com', password: 'p' });
        entriesReset();
        await a.refresh();
      }],
      ['GET', '/api/auth/me', (a) => a.whoami()],
      ['POST', '/api/auth/token/revoke', async (a) => {
        await a.login({ email: 'ada@example.com', password: 'p' });
        entriesReset();
        await a.logout();
      }],
      ['POST', '/api/otp/request', (a) => otp(a).request({ destination: 'ada@example.com', channel: 'email', purpose: 'login' })],
      ['POST', '/api/otp/verify', (a) => otp(a).verify({ otp_id: 'o1', code: '123456' })],
      ['POST', '/api/auth/login/2fa/resend', (a) => mfa(a).resend({ kind: '2fa_token', token: 't' })],
      ['POST', '/api/auth/github/callback', (a) => social(a).completeFromCallback('github', { code: 'c', state: 's' })],
    ];
    let reset: () => void = () => {};
    const entriesReset = (): void => reset();
    for (const [method, path, run] of table) {
      const { auth, entries } = setup(responder);
      reset = () => {
        entries.length = 0;
      };
      await run(auth);
      expect(entries, path).toHaveLength(1);
      expect(entries[0]).toMatchObject({ method, path, status: expect.any(Number), attempt: 1, code: null, errorCode: null });
      expect(entries[0]?.durationMs).toBeGreaterThanOrEqual(0);
    }
  });

  it('entries never contain headers, bodies or query strings', async () => {
    const { auth, entries } = setup(
      (url) =>
        url.pathname.endsWith('/auth/me')
          ? json({ message: 'no', access_token: 'at-leak', refresh_token: 'rt-leak' }, 401, { 'Set-Cookie': 'sid=cookie-leak' })
          : json({ token: { ...pair, access_token: 'at-leak', refresh_token: 'rt-leak' } }, 200, { 'Set-Cookie': 'sid=cookie-leak' }),
      { endpoints: { ...ENDPOINTS, whoami: '/auth/me?token=query-leak#frag-leak' } },
    );
    await auth.login({ email: 'ada@example.com', password: 'pw-leak', code: 'otp-leak' }).catch(() => {});
    await otp(auth).verify({ otp_id: 'o1', code: 'otp-leak' }).catch(() => {});
    await auth.whoami().catch(() => {});
    await auth.http({ method: 'GET', endpoint: '/x?token=query-leak#frag-leak', headers: { Authorization: 'Bearer at-leak', Cookie: 'sid=cookie-leak' } }).catch(() => {});
    expect(entries.length).toBeGreaterThanOrEqual(4);
    for (const e of entries) {
      expect(Object.keys(e).sort()).toEqual(ALLOWED_KEYS);
      const s = JSON.stringify(e);
      for (const leak of ['pw-leak', 'otp-leak', 'at-leak', 'rt-leak', 'query-leak', 'frag-leak', 'cookie-leak', 'Bearer', 'Authorization', '?', '#']) {
        expect(s).not.toContain(leak);
      }
    }
    expect(entries.map((e) => e.path)).toContain('/api/x');
  });

  it('a failing 200 envelope entry carries code and errorCode', async () => {
    for (const errorCode of [4001, '4001']) {
      const { auth, entries } = setup(() => json({ success: false, error_code: errorCode, message: 'bad', data: null, meta: {} }), { unwrap: 'sp-laravel-api' });
      await auth.login({ email: 'ada@example.com', password: 'p' }).catch(() => {});
      expect(entries).toHaveLength(1);
      expect(entries[0]).toMatchObject({ status: 200, code: 'request_failed', errorCode: 4001 });
    }
  });

  it('a non-2xx entry carries the error code, error_code and request id', async () => {
    const { auth, entries } = setup(() => json({ message: 'slow down', error_code: 42 }, 429, { 'X-Request-Id': 'req-1' }));
    await expect(auth.login({ email: 'ada@example.com', password: 'p' })).rejects.toMatchObject({ code: 'rate_limited' });
    expect(entries[0]).toMatchObject({ status: 429, code: 'rate_limited', errorCode: 42, requestId: 'req-1' });
  });

  it('reads the request id from the header, else from meta.request_id', async () => {
    const a = setup(() => json({ token: pair }, 200, { 'X-Request-Id': 'hdr-1' }));
    await a.auth.login({ email: 'ada@example.com', password: 'p' });
    const b = setup(() => json({ token: pair, meta: { request_id: 'meta-1' } }));
    await b.auth.login({ email: 'ada@example.com', password: 'p' });
    expect(a.entries[0]?.requestId).toBe('hdr-1');
    expect(b.entries[0]?.requestId).toBe('meta-1');
  });

  it('a throwing sink does not change the request result', async () => {
    const { auth } = setup(() => json({ token: pair }), { logger: createAuthLogger({ sink: () => { throw new Error('sink boom'); } }) });
    await expect(auth.login({ email: 'ada@example.com', password: 'p' })).resolves.toEqual({ status: 'authenticated' });
    const failing = setup(() => json({ message: 'no' }, 422), { logger: createAuthLogger({ sink: () => { throw new Error('sink boom'); } }) });
    await expect(failing.auth.login({ email: 'ada@example.com', password: 'p' })).rejects.toMatchObject({ code: 'invalid_code', status: 422 });
  });

  describe('rejecting sinks', () => {
    const unhandled: unknown[] = [];
    const onUnhandled = (r: unknown): void => void unhandled.push(r);
    afterEach(() => process.off('unhandledRejection', onUnhandled));

    it('a rejected sink promise does not change the request result', async () => {
      process.on('unhandledRejection', onUnhandled);
      const thenable = { then: (): never => { throw new Error('thenable boom'); } };
      for (const sink of [() => Promise.reject(new Error('sink rejected')), () => thenable]) {
        const { auth } = setup(() => json({ token: pair }), { logger: createAuthLogger({ sink }) });
        await expect(auth.login({ email: 'ada@example.com', password: 'p' })).resolves.toEqual({ status: 'authenticated' });
      }
      await new Promise((r) => setTimeout(r, 20));
      await vi.waitFor(() => expect(unhandled).toEqual([]));
    });
  });

  it('sanitises the request id (control characters, line separators, cap by code points)', async () => {
    const ids = ['a\nb\r\nc', 'x\u001b[31mred\u001b[0m', 'p q r', 'y'.repeat(10_000), `${'z'.repeat(127)}😀tail`, '\n ', 'tab\there\u009fend'];
    const out: (string | null)[] = [];
    for (const id of ids) {
      const { auth, entries } = setup(() => json({ token: pair, meta: { request_id: id } }));
      await auth.login({ email: 'ada@example.com', password: 'p' });
      out.push(entries[0]?.requestId ?? null);
    }
    expect(out[0]).toBe('abc');
    expect(out[1]).toBe('x[31mred[0m');
    expect(out[2]).toBe('pqr');
    expect(out[3]).toBe('y'.repeat(128));
    expect(out[4]).toBe(`${'z'.repeat(127)}😀`);
    expect(out[4]?.endsWith('\ud83d')).toBe(false);
    expect(out[5]).toBeNull();
    expect(out[6]).toBe('tabhereend');
  });

  it('an aborted or network-failed call still yields an entry', async () => {
    const net = setup(() => Promise.reject(new TypeError('Failed to fetch https://x?token=leak')));
    await expect(net.auth.login({ email: 'ada@example.com', password: 'p' })).rejects.toMatchObject({ code: 'network' });
    expect(net.entries).toHaveLength(1);
    expect(net.entries[0]).toMatchObject({ status: null, code: 'network', errorCode: null });
    expect(JSON.stringify(net.entries[0])).not.toContain('leak');

    const ac = new AbortController();
    const hung = setup((_u, init) => new Promise<Response>((_res, rej) => init?.signal?.addEventListener('abort', () => rej(new Error('aborted')))));
    const p = hung.auth.http({ method: 'GET', endpoint: '/slow', signal: ac.signal });
    ac.abort(new Error('caller reason'));
    await expect(p).rejects.toThrow('caller reason');
    expect(hung.entries).toHaveLength(1);
    expect(hung.entries[0]).toMatchObject({ status: null, code: 'aborted', path: '/api/slow' });

    const timeout = setup((_u, init) => new Promise<Response>((_res, rej) => init?.signal?.addEventListener('abort', () => rej(new Error('x')))), { timeoutMs: 10 });
    await expect(timeout.auth.http({ method: 'GET', endpoint: '/slow' })).rejects.toMatchObject({ code: 'timeout' });
    expect(timeout.entries[0]).toMatchObject({ status: null, code: 'timeout' });
  });

  it('an untrusted error string never reaches the entry code', async () => {
    for (const hostile of ['Bearer leak token', 'bad\nline\u001b[31mred', 'x'.repeat(200)]) {
      const { auth, entries } = setup(() => json({ error: hostile, error_description: 'd' }, 400));
      await auth.login({ email: 'ada@example.com', password: 'p' }).catch(() => {});
      expect(entries[0]?.code).toBe('unknown');
      const s = JSON.stringify(entries[0]);
      for (const part of ['Bearer', 'leak', 'token', 'line', 'red', 'xxxx']) expect(s).not.toContain(part);
    }
    const ok = setup(() => json({ error: 'invalid_client' }, 401));
    await ok.auth.login({ email: 'ada@example.com', password: 'p' }).catch(() => {});
    expect(ok.entries[0]?.code).toBe('invalid_client');
  });

  describe('a hand-written logger that throws', () => {
    const entry = { finish: () => { throw new Error('finish boom'); } };
    it('in start leaves the request unchanged', async () => {
      const logger = { start: () => { throw new Error('start boom'); } };
      const { auth } = setup(() => json({ token: pair }), { logger });
      await expect(auth.login({ email: 'ada@example.com', password: 'p' })).resolves.toEqual({ status: 'authenticated' });
    });
    it('in finish on the success path returns the result', async () => {
      const { auth } = setup(() => json({ token: pair }), { logger: { start: () => entry } });
      await expect(auth.login({ email: 'ada@example.com', password: 'p' })).resolves.toEqual({ status: 'authenticated' });
    });
    it('in finish on the error path rethrows the original error', async () => {
      const { auth } = setup(() => json({ message: 'no' }, 422), { logger: { start: () => entry } });
      await expect(auth.login({ email: 'ada@example.com', password: 'p' })).rejects.toMatchObject({ code: 'invalid_code', status: 422 });
    });
  });
});
