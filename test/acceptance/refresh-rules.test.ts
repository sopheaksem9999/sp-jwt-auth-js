// Spec §7 coverage: "Rule 4.5 has a test per numbered point." One thin scenario per bullet of §4.5, through the
// PUBLIC API only (the package entry, as an app imports it), titled with the rule it proves. The deep cases live
// in the suites named in RULE_MAP; this file is the map plus a fast end-to-end check of each rule.
// Edge-safe (runs in both vitest projects).
import { afterEach, describe, expect, it, vi } from 'vitest';
import { clientCredentials, createCrossTab, createJwtAuth, memoryStore, presets, userSession } from '../../src';
import type { AuthEvent, CrossTab, JwtAuthOptions, LockManagerLike, TokenStore, Tokens } from '../../src';

/** §4.5 rule → the deep tests that cover its edge cases (file: describe / it). */
export const RULE_MAP = {
  'rule 1: proactive refresh': ['test/core/refresh.test.ts: proactive refresh in getAccessToken (ahead window, custom ahead, exp in the past, expires_in fallback, JWT exp wins)'],
  'rule 2: single-flight in a process': ['test/core/refresh.test.ts: createRefresher; handleUnauthorized "concurrent calls share one refresh"; "getAccessToken and handleUnauthorized running together share one flight"'],
  'rule 3: single-flight across tabs': ['test/core/crosstab.test.ts: two instances sharing a store (two tabs)', 'test/core/cookie.test.ts: cookie transport: tabs; broadcast grace after a contended lock'],
  'rule 4: old access tokens die on rotation, retried once': ['test/core/refresh.test.ts: handleUnauthorized with the failed request', 'test/core/presets.test.ts: whoami "retries once after a 401" / "does not retry twice"'],
  'rule 5: refresh failure semantics': ['test/core/refresh.test.ts: refresh failure (401 ends the session; network/5xx/4xx keep tokens)'],
  'rule 6: clientCredentials': ['test/core/modes.test.ts: clientCredentials (expires_in 0 → defaultTtlSeconds, refreshAheadSeconds renewal, 50 concurrent → 1, concurrent 401s)'],
} as const;

const b64url = (s: string): string => btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const now = (): number => Math.floor(Date.now() / 1000);
const jwt = (ttl: number, jti: string): string => `${b64url('{"alg":"none"}')}.${b64url(JSON.stringify({ sub: '7', exp: now() + ttl, jti }))}.sig`;
const json = (body: unknown, status = 200): Response => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

const OLD = jwt(30, 'old'); // inside the default 60 s refresh-ahead window
const NEW = jwt(900, 'new');
const pair = { token: { access_token: NEW, refresh_token: 'r2', expires_in: 900, token_type: 'Bearer' } };
const nearExpiry = (): Tokens => ({ accessToken: OLD, refreshToken: 'r1', expiresAt: now() + 30, deviceId: 'd1' });

interface Call { path: string; bearer: string | null }
type Handler = (c: Call) => Response | Promise<Response>;

/** A fake host on the spJwtTest preset; refresh answers `pair` unless the handler says otherwise. */
async function app(handler: Handler, o: { tokens?: Tokens; store?: TokenStore; crossTab?: CrossTab; extra?: Partial<JwtAuthOptions> } = {}) {
  const store = o.store ?? memoryStore();
  if (!o.store) await store.set(o.tokens ?? nearExpiry());
  const calls: Call[] = [];
  const events: AuthEvent[] = [];
  const fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const c = { path: new URL(String(input)).pathname, bearer: new Headers(init?.headers).get('authorization') };
    calls.push(c);
    return handler(c);
  }) as typeof globalThis.fetch;
  const mode = userSession({ storage: store, ...(o.crossTab ? { crossTab: { instance: o.crossTab } } : {}) });
  const auth = createJwtAuth({ baseUrl: 'https://api.test', ...presets.spJwtTest, mode, fetch, onEvent: (e) => events.push(e), ...o.extra });
  await auth.ready();
  return { auth, calls, events, store, refreshes: () => calls.filter((c) => c.path === '/auth/refresh').length };
}

afterEach(() => {
  vi.useRealTimers();
});

describe('§4.5 refresh rules', () => {
  it('rule 1: proactive refresh — refreshes when exp − now < refreshAheadSeconds, not before', async () => {
    const near = await app(() => json(pair));
    expect(await near.auth.getAccessToken()).toBe(NEW);
    expect(near.refreshes()).toBe(1);

    const fresh = await app(() => json(pair), { tokens: { accessToken: NEW, refreshToken: 'r1', expiresAt: now() + 900 } });
    expect(await fresh.auth.getAccessToken()).toBe(NEW);
    expect(fresh.calls).toHaveLength(0);

    // Opaque access token: the expires_in-based expiresAt decides.
    const opaque = await app(() => json(pair), { tokens: { accessToken: 'opaque', refreshToken: 'r1', expiresAt: now() + 10 } });
    expect(await opaque.auth.getAccessToken()).toBe(NEW);
  });

  it('rule 2: single-flight in a process — 100 callers and a 401 waiting on the flight share one refresh', async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const { auth, refreshes } = await app(async () => {
      await gate;
      return json(pair);
    });
    const tokens = Promise.all(Array.from({ length: 100 }, () => auth.getAccessToken()));
    const retry = auth.handleUnauthorized({ headers: { Authorization: `Bearer ${OLD}` } });
    release();
    expect(new Set(await tokens)).toEqual(new Set([NEW]));
    expect(await retry).toBe(true); // the 401'd request may retry once, with the new token
    expect(refreshes()).toBe(1);
  });

  it('rule 3: single-flight across tabs — Web Lock + re-read store: two tabs at expiry make one refresh; logout reaches the other tab', async () => {
    const store = memoryStore();
    await store.set(nearExpiry());
    const { locks, channel } = fakeTabs();
    const a = await app(() => json(pair), { store, crossTab: createCrossTab('k', { locks, channel }) });
    const b = await app(() => json(pair), { store, crossTab: createCrossTab('k', { locks, channel }) });

    expect(await Promise.all([a.auth.getAccessToken(), b.auth.getAccessToken()])).toEqual([NEW, NEW]);
    expect(a.refreshes() + b.refreshes()).toBe(1); // the second tab adopted the pair inside the lock
    expect([...a.events, ...b.events].filter((e) => e.type === 'refresh')).toEqual(
      expect.arrayContaining([{ type: 'refresh' }, { type: 'refresh', adopted: true }]),
    );

    await a.auth.logout();
    await vi.waitFor(() => expect(b.auth.getState().status).toBe('anonymous')); // via the broadcast, no request
    expect(b.calls.filter((c) => c.path !== '/auth/refresh')).toHaveLength(0);
  });

  it('rule 4: old access tokens die on rotation — a 401 with the old token is retried once, never twice', async () => {
    const valid = { accessToken: OLD, refreshToken: 'r1', expiresAt: now() + 900 };
    const ok = await app((c) => (c.path === '/auth/refresh' ? json(pair) : c.bearer === `Bearer ${NEW}` ? json({ id: 1 }) : json({}, 401)), { tokens: valid });
    expect(await ok.auth.whoami()).toEqual({ id: 1 });
    expect(ok.calls.map((c) => c.path)).toEqual(['/me', '/auth/refresh', '/me']);

    const always401 = await app((c) => (c.path === '/auth/refresh' ? json(pair) : json({}, 401)), { tokens: valid });
    await expect(always401.auth.whoami()).rejects.toMatchObject({ status: 401 });
    expect(always401.calls.map((c) => c.path)).toEqual(['/me', '/auth/refresh', '/me']); // one retry only
  });

  it('rule 5: refresh failure — 401 ends the session; network error or 5xx keeps the tokens and rejects the call', async () => {
    const ended = await app(() => json({ message: 'reused' }, 401));
    expect(await ended.auth.getAccessToken()).toBeNull();
    expect(await ended.store.get()).toEqual({ deviceId: 'd1' }); // tokens cleared, device id kept
    expect(ended.auth.getState().status).toBe('anonymous');
    expect(ended.events.map((e) => e.type)).toContain('session_ended');

    for (const fail of [() => Promise.reject(new TypeError('Failed to fetch')), () => json({}, 503)]) {
      const kept = await app(fail, { tokens: { ...nearExpiry(), expiresAt: now() - 1 } });
      await expect(kept.auth.handleUnauthorized()).rejects.toMatchObject({ name: 'SpAuthError' });
      expect((await kept.store.get())?.refreshToken).toBe('r1');
      expect(kept.auth.getState().status).toBe('authenticated');
      expect(kept.events.map((e) => e.type)).not.toContain('session_ended');
    }
  });

  it('rule 6: clientCredentials — expires_in 0 falls back to defaultTtlSeconds, renews ahead and on 401, single-flight', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-01-01T00:00:00Z'));
    let n = 0;
    const fetch = (async () => json({ access_token: `tok${++n}`, token_type: 'Bearer', expires_in: 0 })) as typeof globalThis.fetch;
    const auth = createJwtAuth({ baseUrl: 'https://api.test', endpoints: { oauthToken: '/oauth/token' }, mode: clientCredentials({ clientId: 'id', clientSecret: 's', scope: 'read', defaultTtlSeconds: 600 }), fetch });
    expect(new Set(await Promise.all(Array.from({ length: 50 }, () => auth.getAccessToken())))).toEqual(new Set(['tok1']));
    expect(n).toBe(1); // single-flight per instance
    vi.setSystemTime(Date.now() + 530_000); // 70 s left of the 600 s fallback TTL: still valid
    expect(await auth.getAccessToken()).toBe('tok1');
    vi.setSystemTime(Date.now() + 20_000); // 50 s left < refreshAheadSeconds (60): renewed
    expect(await auth.getAccessToken()).toBe('tok2');
    expect(await auth.handleUnauthorized({ headers: { Authorization: 'Bearer tok2' } })).toBe(true); // 401 → re-fetch
    expect(await auth.getAccessToken()).toBe('tok3');
  });

  it('every §4.5 rule has a test in this file and deep references (non-vacuous map)', () => {
    expect(Object.keys(RULE_MAP)).toHaveLength(6);
    for (const refs of Object.values(RULE_MAP)) expect(refs.length).toBeGreaterThan(0);
  });
});

/** Minimal stand-ins for `navigator.locks` (exclusive, FIFO, `ifAvailable` probes) and `BroadcastChannel`. */
function fakeTabs(): { locks: LockManagerLike; channel: (name: string) => BroadcastChannel } {
  const tails = new Map<string, Promise<unknown>>();
  const held = new Map<string, number>();
  const locks = {
    request(name: string, a: unknown, b?: unknown): Promise<unknown> {
      const cb = (typeof a === 'function' ? a : b) as (lock: unknown) => Promise<unknown>;
      if (typeof a === 'object' && (a as { ifAvailable?: boolean }).ifAvailable && (held.get(name) ?? 0) > 0) return Promise.resolve().then(() => cb(null));
      held.set(name, (held.get(name) ?? 0) + 1);
      const run = (tails.get(name) ?? Promise.resolve()).then(() => cb({ name }));
      const tail = run.then(() => undefined, () => undefined);
      void tail.then(() => held.set(name, (held.get(name) ?? 1) - 1));
      tails.set(name, tail);
      return run;
    },
  } as LockManagerLike;
  const open = new Set<{ name: string; listeners: Set<(e: { data: unknown }) => void> }>();
  const channel = (name: string): BroadcastChannel => {
    const self = { name, listeners: new Set<(e: { data: unknown }) => void>() };
    open.add(self);
    return {
      addEventListener: (t: string, l: (e: { data: unknown }) => void) => t === 'message' && self.listeners.add(l),
      removeEventListener: (t: string, l: (e: { data: unknown }) => void) => t === 'message' && self.listeners.delete(l),
      postMessage: (data: unknown) => {
        for (const c of open) if (c !== self && c.name === name) queueMicrotask(() => c.listeners.forEach((l) => l({ data: structuredClone(data) })));
      },
      close: () => open.delete(self),
    } as unknown as BroadcastChannel;
  };
  return { locks, channel };
}
