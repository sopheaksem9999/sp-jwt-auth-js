import { describe, expect, it } from 'vitest';
import { createJwtAuth, memoryStore, userSession } from '../../src';
import type { AuthEvent, JwtAuth, TokenStore, Unwrap } from '../../src';
import { SpAuthError } from '../../src';
import { sessions } from '../../src/sessions';

function b64url(s: string): string {
  let bin = '';
  for (const b of new TextEncoder().encode(s)) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function jwt(payload: Record<string, unknown>): string {
  return `${b64url(JSON.stringify({ alg: 'none', typ: 'JWT' }))}.${b64url(JSON.stringify(payload))}.sig`;
}
const now = (): number => Math.floor(Date.now() / 1000);
const REFRESH = 'rt-sessions-secret-never-in-errors';
const accessWith = (extra: Record<string, unknown>): string => jwt({ sub: '7', exp: now() + 900, ...extra });
const ACCESS = accessWith({ sid: 's-current' });

const ENDPOINTS = {
  sessions: '/auth/sessions',
  sessionRevoke: '/auth/sessions/:sid',
  sessionRevokeOthers: '/auth/sessions/revoke-others',
  deviceRevoke: '/auth/devices/:deviceId',
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

interface Call {
  method: string;
  url: string;
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
  o: { endpoints?: Record<string, string>; access?: string | null; unwrap?: Unwrap; skipReady?: boolean } = {},
): Promise<Setup> {
  const calls: Call[] = [];
  const f = (async (input: string | URL, init?: RequestInit): Promise<Response> => {
    const c: Call = {
      method: init?.method ?? 'GET',
      url: String(input),
      path: new URL(String(input)).pathname,
      headers: new Headers(init?.headers),
      body: typeof init?.body === 'string' ? init.body : undefined,
    };
    calls.push(c);
    return respond(c);
  }) as unknown as typeof fetch;
  const store = memoryStore();
  const access = o.access === undefined ? ACCESS : o.access;
  if (access !== null) await store.set({ accessToken: access, refreshToken: REFRESH });
  const events: AuthEvent[] = [];
  const auth = createJwtAuth({
    baseUrl: 'https://api.example.com',
    endpoints: o.endpoints ?? ENDPOINTS,
    mode: userSession({ crossTab: false, storage: store }),
    fetch: f,
    ...(o.unwrap ? { unwrap: o.unwrap } : {}),
    onEvent: (e) => events.push(e),
  });
  if (o.skipReady !== true) await auth.ready();
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
  for (const k of Object.getOwnPropertyNames(v)) {
    out.push(k, ...deepStrings((v as Record<string, unknown>)[k], seen));
  }
  return out;
}

describe('sessions.list', () => {
  it('GETs endpoints.sessions with the bearer and marks current by sid (string compare), passing unknown fields through', async () => {
    const s = await setup(() =>
      json([
        { id: 's-current', deviceId: 'd1', deviceName: 'Laptop', ip: '1.2.3.4', userAgent: 'UA', createdAt: 'x', lastActiveAt: 'y', extra: { a: 1 } },
        { id: 's-other', deviceId: 'd2' },
      ]),
    );
    const list = await sessions(s.auth).list();
    expect(s.calls).toHaveLength(1);
    expect(s.calls[0]?.method).toBe('GET');
    expect(s.calls[0]?.path).toBe('/auth/sessions');
    expect(s.calls[0]?.headers.get('Authorization')).toBe(`Bearer ${ACCESS}`);
    expect(list).toEqual([
      { id: 's-current', current: true, deviceId: 'd1', deviceName: 'Laptop', ip: '1.2.3.4', userAgent: 'UA', createdAt: 'x', lastActiveAt: 'y', extra: { a: 1 } },
      { id: 's-other', current: false, deviceId: 'd2' },
    ]);
  });

  it('compares ids as strings (numeric id vs string sid)', async () => {
    const s = await setup(() => json([{ id: 42 }, { id: 43 }]), { access: accessWith({ sid: '42' }) });
    const list = await sessions(s.auth).list();
    expect(list.map((x) => x.current)).toEqual([true, false]);
  });

  it('no current sid (opaque token) -> every entry current:false', async () => {
    const s = await setup(() => json([{ id: 'a' }]), { access: 'opaque-token' });
    expect((await sessions(s.auth).list())[0]?.current).toBe(false);
  });

  it('accepts { data: [...] } and { sessions: [...] } wrappers, and the configured unwrap', async () => {
    const a = await setup(() => json({ data: [{ id: 'a' }] }), { unwrap: 'laravel' });
    expect(await sessions(a.auth).list()).toEqual([{ id: 'a', current: false }]);
    const b = await setup(() => json({ sessions: [{ id: 'b' }] }));
    expect(await sessions(b.auth).list()).toEqual([{ id: 'b', current: false }]);
    const c = await setup(() => json({ payload: [{ id: 'c' }] }), { unwrap: (x) => (x as { payload: unknown }).payload });
    expect(await sessions(c.auth).list()).toEqual([{ id: 'c', current: false }]);
  });

  it('a body that is not a list throws unknown (module sessions), fixed message', async () => {
    const s = await setup(() => json({ secretish: 'tok-abc-123' }));
    const e = await caught(sessions(s.auth).list());
    expect([e.code, e.module]).toEqual(['unknown', 'sessions']);
    expect(e.message).not.toContain('tok-abc-123');
    expect(e.body ?? null).toBeNull();
  });

  it('a throwing function unwrap -> unknown (module sessions); no raw error or body in the chain', async () => {
    const s = await setup(() => json({ nothing: 'leak-me-body' }), {
      unwrap: () => {
        throw new Error('raw unwrap failure leak-me-body');
      },
    });
    const e = await caught(sessions(s.auth).list());
    expect([e.code, e.module]).toEqual(['unknown', 'sessions']);
    expect(deepStrings(e).join('|')).not.toContain('leak-me-body');
  });

  it('401 and 5xx map to SpAuthError with module sessions', async () => {
    const s = await setup(() => json({ message: 'x' }, 503));
    const e = await caught(sessions(s.auth).list());
    expect(e.module).toBe('sessions');
    expect(e.status).toBe(503);
  });
});

describe('sessions.revoke / revokeDevice', () => {
  it('revoke replaces :sid, DELETE by default, bearer sent, state unchanged for another session', async () => {
    const s = await setup(() => json({}));
    await sessions(s.auth).revoke('s-other');
    expect(s.calls[0]?.method).toBe('DELETE');
    expect(s.calls[0]?.path).toBe('/auth/sessions/s-other');
    expect(s.calls[0]?.headers.get('Authorization')).toBe(`Bearer ${ACCESS}`);
    expect(s.auth.getState().status).toBe('authenticated');
    expect((await s.store.get())?.accessToken).toBe(ACCESS);
  });

  it('method option POST', async () => {
    const s = await setup(() => json({}));
    await sessions(s.auth, { method: 'POST' }).revoke('s-other');
    expect(s.calls[0]?.method).toBe('POST');
    await sessions(s.auth, { method: 'POST' }).revokeDevice('d1');
    expect(s.calls[1]?.method).toBe('POST');
  });

  it('empty 204 response is fine', async () => {
    const s = await setup(() => new Response(null, { status: 204 }));
    await expect(sessions(s.auth).revoke('s-other')).resolves.toBeUndefined();
  });

  it('revoking the CURRENT session clears the local session after success (compared as strings)', async () => {
    const s = await setup(() => json({}));
    await sessions(s.auth).revoke('s-current');
    expect(s.auth.getState().status).toBe('anonymous');
    expect(await s.store.get()).toBeNull();
    const n = await setup(() => json({}), { access: accessWith({ sid: 42 }) });
    await sessions(n.auth).revoke('42');
    expect(n.auth.getState().status).toBe('anonymous');
  });

  it('a failed revoke of the current session keeps the session', async () => {
    const s = await setup(() => json({ message: 'boom' }, 500));
    await caught(sessions(s.auth).revoke('s-current'));
    expect(s.auth.getState().status).toBe('authenticated');
    expect((await s.store.get())?.accessToken).toBe(ACCESS);
  });

  it('revokeDevice replaces :deviceId; the session is left alone', async () => {
    const s = await setup(() => json({}));
    await sessions(s.auth).revokeDevice('dev-1');
    expect(s.calls[0]?.method).toBe('DELETE');
    expect(s.calls[0]?.path).toBe('/auth/devices/dev-1');
    expect(s.calls[0]?.headers.get('Authorization')).toBe(`Bearer ${ACCESS}`);
    expect(s.auth.getState().status).toBe('authenticated');
  });

  it('hostile values are encoded and cannot alter the path', async () => {
    for (const v of ['a/b', 'a?x=1', 'a#frag', 'a/../b', '../../admin', 'a b', "a'$&b", '%2e%2e']) {
      const s = await setup(() => json({}));
      await sessions(s.auth).revoke(v);
      await sessions(s.auth).revokeDevice(v);
      const u0 = new URL(s.calls[0]?.url ?? '');
      const u1 = new URL(s.calls[1]?.url ?? '');
      expect(u0.pathname).toBe(`/auth/sessions/${encodeURIComponent(v)}`);
      expect(u1.pathname).toBe(`/auth/devices/${encodeURIComponent(v)}`);
      expect(u0.search).toBe('');
      expect(u0.hash).toBe('');
      expect(u0.pathname.split('/')).toHaveLength(4);
    }
  });

  it('values that are dot segments or empty are rejected without a request', async () => {
    for (const v of ['', '.', '..']) {
      const s = await setup(() => json({}));
      const e = await caught(sessions(s.auth).revoke(v));
      expect(e.module).toBe('sessions');
      expect(s.calls).toHaveLength(0);
      await caught(sessions(s.auth).revokeDevice(v));
      expect(s.calls).toHaveLength(0);
    }
  });
});

describe('sessions.revokeOthers', () => {
  it('POSTs exactly { except_sid } with the current sid and the bearer', async () => {
    const s = await setup(() => json({}));
    await sessions(s.auth).revokeOthers();
    expect(s.calls).toHaveLength(1);
    expect(s.calls[0]?.method).toBe('POST');
    expect(s.calls[0]?.path).toBe('/auth/sessions/revoke-others');
    expect(JSON.parse(s.calls[0]?.body ?? '')).toEqual({ except_sid: 's-current' });
    expect(s.calls[0]?.headers.get('Authorization')).toBe(`Bearer ${ACCESS}`);
    expect(s.auth.getState().status).toBe('authenticated');
  });

  it('no current sid -> not_configured (module sessions) and NO request', async () => {
    for (const access of ['opaque-token', accessWith({}), null]) {
      const s = await setup(() => json({}), { access });
      const e = await caught(sessions(s.auth).revokeOthers());
      expect([e.code, e.module]).toEqual(['not_configured', 'sessions']);
      expect(e.message).toMatch(/no current session id/i);
      expect(s.calls).toHaveLength(0);
    }
  });

  it('revokeOthersBody option overrides the body and receives the sid', async () => {
    const seen: (string | null)[] = [];
    const s = await setup(() => json({}));
    await sessions(s.auth, {
      revokeOthersBody: (sid) => {
        seen.push(sid);
        return { keep: sid, all: true };
      },
    }).revokeOthers();
    expect(seen).toEqual(['s-current']);
    expect(JSON.parse(s.calls[0]?.body ?? '')).toEqual({ keep: 's-current', all: true });
  });
});

describe('sessions: not_configured per endpoint', () => {
  it('each unset endpoint throws not_configured with module sessions and sends nothing', async () => {
    const calls: [string, (m: ReturnType<typeof sessions>) => Promise<unknown>][] = [
      ['sessions', (m) => m.list()],
      ['sessionRevoke', (m) => m.revoke('x')],
      ['sessionRevokeOthers', (m) => m.revokeOthers()],
      ['deviceRevoke', (m) => m.revokeDevice('x')],
    ];
    for (const [name, run] of calls) {
      const s = await setup(() => json({}), { endpoints: {} });
      const e = await caught(run(sessions(s.auth)));
      expect([name, e.code, e.module]).toEqual([name, 'not_configured', 'sessions']);
      expect(s.calls).toHaveLength(0);
    }
  });
});

describe('sessions: secrets', () => {
  it('errors (incl. cause chain), events and state never carry tokens', async () => {
    const s = await setup(() => json({ message: 'denied', access_token: 'body-token-xyz' }, 500));
    const errs = [await caught(sessions(s.auth).list()), await caught(sessions(s.auth).revoke('s-other')), await caught(sessions(s.auth).revokeOthers())];
    // An HTTP-status error keeps the host body by core design; messages and the cause chain must be clean.
    const all = [...errs.map((e) => `${e.message}|${e.name}|${deepStrings(e.cause).join('|')}`), ...deepStrings([s.events, s.auth.getState()])].join('|');
    for (const secret of [REFRESH, ACCESS, 'body-token-xyz']) expect(all).not.toContain(secret);
  });
});

describe('sessions: fresh client (no ready() before the call)', () => {
  it('revoke(currentSid) clears the local session', async () => {
    const s = await setup(() => json({}), { skipReady: true });
    await sessions(s.auth).revoke('s-current');
    expect(s.auth.getState().status).toBe('anonymous');
    expect(await s.store.get()).toBeNull();
  });

  it('revokeOthers sends { except_sid } for a signed-in user', async () => {
    const s = await setup(() => json({}), { skipReady: true });
    await sessions(s.auth).revokeOthers();
    expect(JSON.parse(s.calls[0]?.body ?? '')).toEqual({ except_sid: 's-current' });
  });

  it('list marks current', async () => {
    const s = await setup(() => json([{ id: 's-current' }]), { skipReady: true });
    expect((await sessions(s.auth).list())[0]?.current).toBe(true);
  });
});

describe('sessions: endpoint without its placeholder', () => {
  it('sessionRevoke without :sid and deviceRevoke without :deviceId -> not_configured, no request', async () => {
    const s = await setup(() => json({}), { endpoints: { ...ENDPOINTS, sessionRevoke: '/auth/sessions', deviceRevoke: '/auth/devices' } });
    const a = await caught(sessions(s.auth).revoke('x'));
    const b = await caught(sessions(s.auth).revokeDevice('x'));
    expect([a.code, a.module, b.code, b.module]).toEqual(['not_configured', 'sessions', 'not_configured', 'sessions']);
    expect(s.calls).toHaveLength(0);
  });
});
