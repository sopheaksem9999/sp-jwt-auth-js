import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createJwtAuth, userSession } from '../../src/core/create-jwt-auth';
import type { AuthEvent, JwtAuth, UserSessionOptions } from '../../src/core/create-jwt-auth';
import { SpAuthError } from '../../src/core/errors';
import { ensureDeviceId, memoryStore } from '../../src/core/stores';
import type { TokenStore, Tokens } from '../../src/core/stores';
import { findTokenPair } from '../../src/core/unwrap';
import { social } from '../../src/social';

// Fixes from the final whole-branch review (cross-tab default for the cookie transport, mode reuse,
// guarded unwrap, sanitised causes and events, concurrency windows, small correctness items).

function b64url(s: string): string {
  let bin = '';
  for (const b of new TextEncoder().encode(s)) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function jwt(payload: Record<string, unknown>): string {
  return `${b64url(JSON.stringify({ alg: 'none', typ: 'JWT' }))}.${b64url(JSON.stringify(payload))}.sig`;
}

const now = (): number => Math.floor(Date.now() / 1000);
const SECRET = 'secret-value-that-must-never-leak-7f3a';
const nearExpiry = jwt({ sub: '7', exp: now() + 30 });
const fresh1 = jwt({ sub: '7', exp: now() + 900 });
const fresh2 = jwt({ sub: '7', exp: now() + 1800 });
const fresh3 = jwt({ sub: '9', exp: now() + 2700 });

function pair(access: string, refresh?: string): Record<string, unknown> {
  const p: Record<string, unknown> = { access_token: access, expires_in: 900, token_type: 'Bearer' };
  if (refresh) p.refresh_token = refresh;
  return p;
}

function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } });
}

interface Call {
  method: string;
  url: string;
  path: string;
  headers: Headers;
}

type Handler = (c: Call) => Response | Promise<Response>;

function fakeFetch(handler: Handler): { fetch: typeof fetch; calls: Call[] } {
  const calls: Call[] = [];
  const f = (async (input: string | URL, init?: RequestInit): Promise<Response> => {
    const url = String(input);
    const c: Call = { method: init?.method ?? 'GET', url, path: new URL(url, 'https://relative.invalid').pathname, headers: new Headers(init?.headers) };
    calls.push(c);
    return handler(c);
  }) as unknown as typeof fetch;
  return { fetch: f, calls };
}

async function flush(): Promise<void> {
  for (let i = 0; i < 60; i++) await Promise.resolve();
}

async function caught(p: Promise<unknown>): Promise<SpAuthError> {
  try {
    await p;
  } catch (e) {
    expect(e).toBeInstanceOf(SpAuthError);
    return e as SpAuthError;
  }
  throw new Error('expected a rejection');
}

/** The error, its cause and anything else a logger would print must not contain the secret. */
function expectNoSecret(e: SpAuthError): void {
  expect(e.body).toBeNull();
  expect(e.response).toBeNull();
  const cause = e.cause as Error | undefined;
  if (cause !== undefined) {
    expect(cause.message).toBe('Underlying error details omitted');
    expect(Object.keys(cause).filter((k) => k !== 'name')).toEqual([]);
  }
  expect(JSON.stringify({ e, cause, msg: e.message, stack: cause?.message })).not.toContain(SECRET);
}

/** A function-valued `unwrap` that throws an error carrying a secret, for the response kinds selected by `when`. */
function throwingUnwrap(when: (body: unknown) => boolean): (body: unknown) => unknown {
  return (body) => {
    if (!when(body)) return body;
    const err = new Error(`unwrap failed: ${SECRET}`) as Error & { payload?: unknown };
    err.name = 'ParseError';
    err.payload = { token: SECRET };
    throw err;
  };
}

/** A store whose next `set` (after `arm()`) waits for `release()`. */
function gatedStore(): TokenStore & { arm(): void; release(): void; armed: Promise<void> } {
  const inner = memoryStore();
  let gate: Promise<void> | null = null;
  let open!: () => void;
  let reached!: () => void;
  const s = {
    get: () => inner.get(),
    async set(t: Tokens | null): Promise<void> {
      if (gate) {
        const g = gate;
        gate = null;
        reached();
        await g;
      }
      await inner.set(t);
    },
    arm() {
      gate = new Promise<void>((r) => (open = r));
      s.armed = new Promise<void>((r) => (reached = r));
    },
    release() {
      open();
    },
    armed: Promise.resolve(),
  };
  return s;
}

// ---------------------------------------------------------------------------------------------------------------
// Fake browser globals for the default cross-tab path (feature detection of navigator.locks / BroadcastChannel).

type LockCb = (lock: unknown) => Promise<unknown>;

function fakeLocks(): { request(name: string, a: LockCb | { ifAvailable?: boolean }, b?: LockCb): Promise<unknown>; granted: string[] } {
  const tails = new Map<string, Promise<unknown>>();
  const busy = new Map<string, number>();
  const granted: string[] = [];
  return {
    granted,
    request(name, a, b) {
      const cb = (typeof a === 'function' ? a : b)!;
      if (typeof a === 'object' && a.ifAvailable === true && (busy.get(name) ?? 0) > 0) return Promise.resolve().then(() => cb(null));
      busy.set(name, (busy.get(name) ?? 0) + 1);
      const run = (tails.get(name) ?? Promise.resolve()).then(() => {
        granted.push(name);
        return cb({ name });
      });
      const tail = run.then(
        () => undefined,
        () => undefined,
      );
      void tail.then(() => busy.set(name, (busy.get(name) ?? 1) - 1));
      tails.set(name, tail);
      return run;
    },
  };
}

interface Bus {
  names: string[];
  posted: unknown[];
  held: boolean;
  release(): void;
}

/** Installs a global `BroadcastChannel` whose instances talk to each other in memory. */
function installChannels(): Bus {
  const open = new Set<{ name: string; listeners: Set<(e: { data: unknown }) => void> }>();
  const pending: (() => void)[] = [];
  const bus: Bus = {
    names: [],
    posted: [],
    held: false,
    release() {
      bus.held = false;
      for (const run of pending.splice(0)) queueMicrotask(run);
    },
  };
  class FakeChannel {
    readonly listeners = new Set<(e: { data: unknown }) => void>();
    constructor(readonly name: string) {
      bus.names.push(name);
      open.add(this);
    }
    addEventListener(t: string, l: (e: { data: unknown }) => void): void {
      if (t === 'message') this.listeners.add(l);
    }
    removeEventListener(t: string, l: (e: { data: unknown }) => void): void {
      if (t === 'message') this.listeners.delete(l);
    }
    postMessage(data: unknown): void {
      const wire = JSON.stringify(data);
      bus.posted.push(JSON.parse(wire));
      for (const c of open) {
        if (c === this || c.name !== this.name) continue;
        const run = (): void => {
          for (const l of [...c.listeners]) l({ data: JSON.parse(wire) });
        };
        if (bus.held) pending.push(run);
        else queueMicrotask(run);
      }
    }
    close(): void {
      open.delete(this);
    }
  }
  vi.stubGlobal('BroadcastChannel', FakeChannel);
  return bus;
}

type VersionsHolder = { versions?: Record<string, string | undefined> };
let restoreVersions: (() => void) | null = null;

/** Sets `process.versions.node` (present = a Node-like runtime) for this test; `afterEach` restores it. */
function setNodeVersion(node: string | undefined): void {
  const proc = (globalThis as { process?: VersionsHolder }).process;
  if (!proc) {
    if (node !== undefined) {
      vi.stubGlobal('process', { versions: { node } });
    }
    return;
  }
  const desc = Object.getOwnPropertyDescriptor(proc, 'versions');
  const next: Record<string, string | undefined> = { ...(proc.versions ?? {}) };
  if (node === undefined) delete next.node;
  else next.node = node;
  Object.defineProperty(proc, 'versions', { value: next, configurable: true, enumerable: true, writable: false });
  const prev = restoreVersions;
  restoreVersions = () => {
    if (desc) Object.defineProperty(proc, 'versions', desc);
    else delete proc.versions;
    prev?.();
  };
}

/**
 * A real browser tab: `process.versions.node` empty, which the package treats as "not Node-like"
 * (whatever the test runner's own runtime is). Empty rather than deleted: Node's own fetch/Headers
 * (undici) read `process.versions.node.split('.')` lazily and would throw without it.
 */
const simulateBrowserRuntime = (): void => setNodeVersion('');
/** A Node-like server runtime (Node, or Deno/Bun emulating it), made explicit so both vitest projects agree. */
const simulateNodeRuntime = (): void => setNodeVersion('24.0.0');

afterEach(() => {
  restoreVersions?.();
  restoreVersions = null;
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  vi.useRealTimers();
});

// ---------------------------------------------------------------------------------------------------------------

describe('cookie transport: cross-tab is ON by default in a browser tab (any store)', () => {
  const endpoints = { login: '/auth/login' };
  // These simulate a real browser: the default must not depend on the test runner being Node.
  beforeEach(() => simulateBrowserRuntime());

  /** A browser tab with the cookie transport and NO crossTab / storage options: the defaults under test. */
  function tab(handler: Handler, opts: UserSessionOptions = {}, baseUrl = 'https://api.example.com') {
    const { fetch, calls } = fakeFetch(handler);
    const events: AuthEvent[] = [];
    const auth = createJwtAuth({ baseUrl, endpoints, mode: userSession({ transport: 'cookie', ...opts }), fetch, onEvent: (e) => events.push(e) });
    return { auth, calls, events };
  }

  it('two tabs restoring at once with the same httpOnly cookie send ONE refresh (memory store, default crossTab)', async () => {
    vi.stubGlobal('document', { cookie: 'sp_csrf=c1' });
    const locks = fakeLocks();
    vi.stubGlobal('navigator', { locks });
    const bus = installChannels();
    let refreshes = 0;
    const handler: Handler = () => {
      refreshes++;
      return json(pair(fresh1), 200, { 'X-SP-CSRF': 'c2' });
    };
    const a = tab(handler);
    const b = tab(handler, { storage: memoryStore() });
    await Promise.all([a.auth.restore(), b.auth.restore()]);
    expect(refreshes).toBe(1);
    expect(a.auth.getState().status).toBe('authenticated');
    expect(b.auth.getState().status).toBe('authenticated');
    expect(await b.auth.getAccessToken()).toBe(fresh1);
    expect(locks.granted.every((n) => n === 'sp-jwt-auth:refresh:cookie:https://api.example.com')).toBe(true);
    expect(locks.granted.length).toBeGreaterThan(0);
    expect(bus.names.every((n) => n === 'sp-jwt-auth:tabs:cookie:https://api.example.com')).toBe(true);
    a.auth.dispose?.();
    b.auth.dispose?.();
  });

  it('two tabs at expiry (signed in) refresh once', async () => {
    vi.stubGlobal('document', { cookie: '' });
    vi.stubGlobal('navigator', { locks: fakeLocks() });
    installChannels();
    let refreshes = 0;
    const handler: Handler = (c) => {
      if (c.path === '/auth/login') return json(pair(nearExpiry), 200, { 'X-SP-CSRF': 'c1' });
      refreshes++;
      return json(pair(fresh2), 200, { 'X-SP-CSRF': 'c2' });
    };
    const a = tab(handler);
    const b = tab(handler);
    await b.auth.restore(); // anonymous (no CSRF yet); b now listens
    await a.auth.login({});
    await flush();
    expect(b.auth.getState().status).toBe('authenticated');
    const [ta, tb] = await Promise.all([a.auth.getAccessToken(), b.auth.getAccessToken()]);
    expect(ta).toBe(fresh2);
    expect(tb).toBe(fresh2);
    expect(refreshes).toBe(1);
    a.auth.dispose?.();
    b.auth.dispose?.();
  });

  it('a relative baseUrl keys the lock by location.origin, else cookie:default', async () => {
    vi.stubGlobal('document', { cookie: 'sp_csrf=c1' });
    const locks = fakeLocks();
    vi.stubGlobal('navigator', { locks });
    installChannels();
    vi.stubGlobal('location', { origin: 'https://app.example.com' });
    const a = tab(() => json(pair(fresh1)), {}, '/api');
    await a.auth.restore();
    expect(locks.granted).toEqual(['sp-jwt-auth:refresh:cookie:https://app.example.com']);
    a.auth.dispose?.();

    vi.stubGlobal('location', undefined);
    const b = tab(() => json(pair(fresh1)), {}, '/api');
    await b.auth.restore();
    expect(locks.granted[locks.granted.length - 1]).toBe('sp-jwt-auth:refresh:cookie:default');
    b.auth.dispose?.();
  });

  it('servers (no document) keep the store-scoped coordinator: no channel, no Web Lock', async () => {
    const request = vi.fn();
    vi.stubGlobal('navigator', { locks: { request } });
    const bus = installChannels();
    let refreshes = 0;
    const handler: Handler = () => {
      refreshes++;
      return json(pair(fresh1), 200, { 'X-SP-CSRF': 'c2' });
    };
    const s1 = memoryStore();
    const s2 = memoryStore();
    await s1.set({ csrf: 'c1' });
    await s2.set({ csrf: 'c1' });
    const a = tab(handler, { storage: s1 });
    const b = tab(handler, { storage: s2 });
    await Promise.all([a.auth.restore(), b.auth.restore()]);
    expect(refreshes).toBe(2); // two users' sessions: nothing shared
    expect(request).not.toHaveBeenCalled();
    expect(bus.names).toEqual([]);
  });

  it('crossTab: false still disables it in a browser tab', async () => {
    vi.stubGlobal('document', { cookie: 'sp_csrf=c1' });
    const request = vi.fn();
    vi.stubGlobal('navigator', { locks: { request } });
    const bus = installChannels();
    const a = tab(() => json(pair(fresh1)), { crossTab: false });
    await a.auth.restore();
    expect(a.auth.getState().status).toBe('authenticated');
    expect(request).not.toHaveBeenCalled();
    expect(bus.names).toEqual([]);
  });

  it('body transport defaults are unchanged (memory store: no channel, no Web Lock even in a tab)', async () => {
    vi.stubGlobal('document', { cookie: '' });
    const request = vi.fn();
    vi.stubGlobal('navigator', { locks: { request } });
    const bus = installChannels();
    const storage = memoryStore();
    await storage.set({ accessToken: nearExpiry, refreshToken: 'rt1', expiresAt: now() + 30 });
    const { fetch } = fakeFetch(() => json(pair(fresh1, 'rt2')));
    const auth = createJwtAuth({ baseUrl: 'https://api.example.com', mode: userSession({ storage }), fetch });
    expect(await auth.getAccessToken()).toBe(fresh1);
    expect(request).not.toHaveBeenCalled();
    expect(bus.names).toEqual([]);
  });

  it('broadcastGraceMs above 2^31-1 is clamped (a larger setTimeout delay would fire at once)', async () => {
    vi.stubGlobal('document', { cookie: '' });
    vi.stubGlobal('navigator', { locks: fakeLocks() });
    const bus = installChannels();
    const spy = vi.spyOn(globalThis, 'setTimeout');
    let refreshes = 0;
    const handler: Handler = (c) => {
      if (c.path === '/auth/login') return json(pair(nearExpiry), 200, { 'X-SP-CSRF': 'c1' });
      refreshes++;
      return json(pair(fresh2), 200, { 'X-SP-CSRF': 'c2' });
    };
    const a = tab(handler, { broadcastGraceMs: 1e12 });
    const b = tab(handler, { broadcastGraceMs: 1e12 });
    await b.auth.restore();
    await a.auth.login({});
    await flush();
    bus.held = true; // a's broadcast arrives after b's (contended) grant: b waits in the grace
    const pa = a.auth.getAccessToken();
    const pb = b.auth.getAccessToken();
    await pa;
    await flush();
    const delays = spy.mock.calls.map((c) => c[1]).filter((d): d is number => typeof d === 'number' && d > 60_000);
    expect(delays).toEqual([2 ** 31 - 1]);
    bus.release();
    expect(await pb).toBe(fresh2);
    expect(refreshes).toBe(1);
    a.auth.dispose?.();
    b.auth.dispose?.();
  });
});

describe('cookie transport: no default cross-tab in a Node-like runtime, even with a global document', () => {
  const endpoints = { login: '/auth/login' };
  beforeEach(() => simulateNodeRuntime());

  function client(handler: Handler, opts: UserSessionOptions = {}) {
    const { fetch, calls } = fakeFetch(handler);
    const auth = createJwtAuth({ baseUrl: 'https://api.example.com', endpoints, mode: userSession({ transport: 'cookie', ...opts }), fetch });
    return { auth, calls };
  }

  it('jsdom-style server: no channel, no Web Lock, and two users never share a token', async () => {
    vi.stubGlobal('document', { cookie: 'sp_csrf=c1' }); // e.g. global-jsdom registered on the server
    const request = vi.fn();
    vi.stubGlobal('navigator', { locks: { request } });
    const bus = installChannels();
    let n = 0;
    const tokens = [fresh1, fresh3];
    const handler: Handler = (c) =>
      c.path === '/auth/login' ? json(pair(fresh2), 200, { 'X-SP-CSRF': 'c-login' }) : json(pair(tokens[n++]!), 200, { 'X-SP-CSRF': `c${n + 1}` });
    const userA = client(handler);
    const userB = client(handler);
    await userA.auth.restore();
    await userB.auth.restore();
    expect(n).toBe(2); // each refreshed for itself
    expect(await userA.auth.getAccessToken()).toBe(fresh1);
    expect(await userB.auth.getAccessToken()).toBe(fresh3);
    await userA.auth.login({}); // a later token for user A reaches nobody else
    await flush();
    expect(await userA.auth.getAccessToken()).toBe(fresh2);
    expect(await userB.auth.getAccessToken()).toBe(fresh3);
    expect(request).not.toHaveBeenCalled();
    expect(bus.names).toEqual([]);
    expect(bus.posted).toEqual([]);
  });

  it('an explicit crossTab: true is still honoured (e.g. an Electron renderer)', async () => {
    vi.stubGlobal('document', { cookie: 'sp_csrf=c1' });
    const locks = fakeLocks();
    vi.stubGlobal('navigator', { locks });
    const bus = installChannels();
    const a = client(() => json(pair(fresh1), 200, { 'X-SP-CSRF': 'c2' }), { crossTab: true });
    await a.auth.restore();
    expect(a.auth.getState().status).toBe('authenticated');
    expect(locks.granted).toEqual(['sp-jwt-auth:refresh:default']);
    expect(bus.names).toEqual(['sp-jwt-auth:tabs:default']);
    a.auth.dispose?.();
  });
});

describe('a mode object reused across clients never shares the default store', () => {
  it('body transport: one hoisted userSession(), two clients, separate tokens', async () => {
    const mode = userSession();
    const { fetch } = fakeFetch(() => json(pair(fresh1, 'rt1')));
    const a = createJwtAuth({ baseUrl: 'https://api.example.com', endpoints: { login: '/auth/login' }, mode, fetch });
    const b = createJwtAuth({ baseUrl: 'https://api.example.com', endpoints: { login: '/auth/login' }, mode, fetch });
    await a.login({});
    expect(await a.getAccessToken()).toBe(fresh1);
    expect(await b.getAccessToken()).toBeNull();
    expect(b.getState().status).toBe('anonymous');
  });

  it('cookie transport: one hoisted mode, two clients, separate stores', async () => {
    const mode = userSession({ transport: 'cookie' });
    const { fetch } = fakeFetch(() => json(pair(fresh1), 200, { 'X-SP-CSRF': 'c-user-a' }));
    const a = createJwtAuth({ baseUrl: 'https://api.example.com', endpoints: { login: '/auth/login' }, mode, fetch });
    const b = createJwtAuth({ baseUrl: 'https://api.example.com', endpoints: { login: '/auth/login' }, mode, fetch });
    await a.login({});
    expect(await a.getAccessToken()).toBe(fresh1);
    await b.restore(); // no CSRF value of its own: anonymous without a request
    expect(b.getState().status).toBe('anonymous');
    expect(await b.getAccessToken()).toBeNull();
  });

  it('an explicit storage is shared by design', async () => {
    const storage = memoryStore();
    const mode = userSession({ storage, crossTab: false });
    const { fetch } = fakeFetch(() => json(pair(fresh1, 'rt1')));
    const a = createJwtAuth({ baseUrl: 'https://api.example.com', endpoints: { login: '/auth/login' }, mode, fetch });
    await a.login({});
    const b = createJwtAuth({ baseUrl: 'https://api.example.com', mode, fetch });
    expect(await b.getAccessToken()).toBe(fresh1);
  });
});

describe('a throwing function-valued unwrap is reported without leaking', () => {
  it('body refresh: SpAuthError(unknown), sanitised cause, refresh_failed, tokens kept', async () => {
    const storage = memoryStore();
    await storage.set({ accessToken: nearExpiry, refreshToken: 'rt1', expiresAt: now() + 30 });
    const events: AuthEvent[] = [];
    const { fetch } = fakeFetch(() => json(pair(fresh1, 'rt2')));
    const auth = createJwtAuth({
      baseUrl: 'https://api.example.com',
      mode: userSession({ storage }),
      unwrap: throwingUnwrap(() => true),
      fetch,
      onEvent: (e) => events.push(e),
    });
    const e = await caught(auth.refresh());
    expect(e.code).toBe('unknown');
    expect(e.module).toBe('refresh');
    expect((e.cause as Error).name).toBe('ParseError');
    expectNoSecret(e);
    expect(events).toContainEqual({ type: 'refresh_failed', status: 0, code: 'unknown' });
    expect((await storage.get())?.refreshToken).toBe('rt1');
  });

  it('cookie refresh: SpAuthError(unknown), sanitised cause, refresh_failed', async () => {
    const storage = memoryStore();
    await storage.set({ csrf: 'c1' });
    const events: AuthEvent[] = [];
    const { fetch } = fakeFetch(() => json(pair(fresh1)));
    const auth = createJwtAuth({
      baseUrl: 'https://api.example.com',
      mode: userSession({ storage, transport: 'cookie', crossTab: false }),
      unwrap: throwingUnwrap(() => true),
      fetch,
      onEvent: (e) => events.push(e),
    });
    const e = await caught(auth.restore());
    expect(e.code).toBe('unknown');
    expect(e.module).toBe('refresh');
    expectNoSecret(e);
    expect(events).toContainEqual({ type: 'refresh_failed', status: 0, code: 'unknown' });
    expect(auth.getState().status).toBe('unknown');
  });

  it('cookie acceptTokens (login): SpAuthError(unknown), sanitised cause, nothing stored', async () => {
    const storage = memoryStore();
    const { fetch } = fakeFetch(() => json(pair(fresh1), 200, { 'X-SP-CSRF': 'c1' }));
    const auth = createJwtAuth({
      baseUrl: 'https://api.example.com',
      endpoints: { login: '/auth/login' },
      mode: userSession({ storage, transport: 'cookie', crossTab: false }),
      unwrap: throwingUnwrap(() => true),
      fetch,
    });
    const e = await caught(auth.login({}));
    expect(e.code).toBe('unknown');
    expectNoSecret(e);
    expect(await storage.get()).toBeNull();
    expect(auth.getState().status).not.toBe('authenticated');
  });

  it('whoami: SpAuthError(unknown, module whoami), sanitised cause', async () => {
    const storage = memoryStore();
    await storage.set({ accessToken: fresh1, refreshToken: 'rt1', expiresAt: now() + 900 });
    const { fetch } = fakeFetch(() => json({ id: 7, secret: SECRET }));
    const auth = createJwtAuth({
      baseUrl: 'https://api.example.com',
      endpoints: { whoami: '/me' },
      mode: userSession({ storage }),
      unwrap: throwingUnwrap(() => true),
      fetch,
    });
    const e = await caught(auth.whoami());
    expect(e.code).toBe('unknown');
    expect(e.module).toBe('whoami');
    expectNoSecret(e);
    expect(auth.getState().user).toBeNull();
  });
});

describe('the logout event carries only { status, code } of a remote failure', () => {
  it('a 500 from the revoke route', async () => {
    const storage = memoryStore();
    await storage.set({ accessToken: fresh1, refreshToken: 'rt1', expiresAt: now() + 900 });
    const events: AuthEvent[] = [];
    const { fetch } = fakeFetch(() => json({ message: `boom ${SECRET}`, token: SECRET }, 500));
    const auth = createJwtAuth({ baseUrl: 'https://api.example.com', mode: userSession({ storage }), fetch, onEvent: (e) => events.push(e) });
    await auth.logout();
    const ev = events.find((e) => e.type === 'logout');
    expect(ev).toEqual({ type: 'logout', everywhere: false, remoteError: { status: 500, code: 'unknown' } });
    expect(JSON.stringify(ev)).not.toContain(SECRET);
  });

  it('a transport failure', async () => {
    const storage = memoryStore();
    await storage.set({ accessToken: fresh1, refreshToken: 'rt1', expiresAt: now() + 900 });
    const events: AuthEvent[] = [];
    const { fetch } = fakeFetch(() => Promise.reject(new TypeError('offline')));
    const auth = createJwtAuth({ baseUrl: 'https://api.example.com', mode: userSession({ storage }), fetch, onEvent: (e) => events.push(e) });
    await auth.logout();
    expect(events.find((e) => e.type === 'logout')).toEqual({ type: 'logout', everywhere: false, remoteError: { status: 0, code: 'network' } });
  });
});

describe('transport failures attach a sanitised cause', () => {
  /** What wrappers such as ofetch's FetchError carry: the request options, Authorization included. */
  function wrapperError(): Error {
    const e = new Error(`[POST] "https://api.example.com/x": <no response> ${SECRET}`) as Error & { options?: unknown; request?: unknown };
    e.name = 'FetchError';
    e.options = { headers: { Authorization: `Bearer ${SECRET}` } };
    e.request = 'https://api.example.com/x';
    return e;
  }

  it('network: only the name survives', async () => {
    const { fetch } = fakeFetch(() => Promise.reject(wrapperError()));
    const auth = createJwtAuth({ baseUrl: 'https://api.example.com', mode: userSession(), fetch });
    const e = await caught(auth.http({ method: 'POST', endpoint: '/x', headers: { Authorization: `Bearer ${SECRET}` } }));
    expect(e.code).toBe('network');
    expect((e.cause as Error).name).toBe('FetchError');
    expectNoSecret(e);
  });

  it('timeout: only the name survives', async () => {
    const f = ((_u: string, init?: RequestInit) =>
      new Promise((_r, reject) => {
        init?.signal?.addEventListener('abort', () => reject(wrapperError()));
      })) as unknown as typeof fetch;
    const auth = createJwtAuth({ baseUrl: 'https://api.example.com', mode: userSession(), fetch: f, timeoutMs: 5 });
    const e = await caught(auth.http({ method: 'GET', endpoint: '/x' }));
    expect(e.code).toBe('timeout');
    expect((e.cause as Error).name).toBe('FetchError');
    expectNoSecret(e);
  });
});

describe('concurrency windows', () => {
  it('cookie: a logout during the refresh store write is not undone (no resurrected session)', async () => {
    const storage = gatedStore();
    await storage.set({ csrf: 'c1' });
    const events: AuthEvent[] = [];
    const { fetch } = fakeFetch((c) => (c.path === '/auth/token/refresh' ? json(pair(fresh1), 200, { 'X-SP-CSRF': 'c2' }) : new Response(null, { status: 204 })));
    const auth = createJwtAuth({
      baseUrl: 'https://api.example.com',
      mode: userSession({ storage, transport: 'cookie', crossTab: false }),
      fetch,
      onEvent: (e) => events.push(e),
    });
    await auth.ready();
    storage.arm();
    const restoring = auth.restore();
    await storage.armed; // the refresh response is being written
    const out = auth.logout();
    await flush();
    storage.release();
    await restoring;
    await out;
    expect(auth.getState().status).toBe('anonymous');
    expect(await auth.getAccessToken()).toBeNull();
    expect((await storage.get())?.csrf).toBeUndefined();
    expect(events.map((e) => e.type)).not.toContain('refresh');
  });

  it('cookie: a login that completes during a refresh is not overwritten by the refresh response', async () => {
    const storage = memoryStore();
    await storage.set({ csrf: 'c1' });
    let releaseRefresh!: (r: Response) => void;
    const { fetch } = fakeFetch((c) =>
      c.path === '/auth/login' ? json(pair(fresh3), 200, { 'X-SP-CSRF': 'c-login' }) : new Promise<Response>((r) => (releaseRefresh = r)),
    );
    const auth = createJwtAuth({
      baseUrl: 'https://api.example.com',
      endpoints: { login: '/auth/login' },
      mode: userSession({ storage, transport: 'cookie', crossTab: false }),
      fetch,
    });
    const restoring = auth.restore();
    await flush();
    await auth.login({});
    releaseRefresh(json(pair(fresh1), 200, { 'X-SP-CSRF': 'c-refresh' }));
    await restoring;
    expect(await auth.getAccessToken()).toBe(fresh3);
    expect(auth.getState().claims?.sub).toBe('9');
    expect((await storage.get())?.csrf).toBe('c-login');
  });

  it('body: a logout during the refresh store write is not undone', async () => {
    const storage = gatedStore();
    await storage.set({ accessToken: nearExpiry, refreshToken: 'rt1', expiresAt: now() + 30, deviceId: 'd1' });
    const { fetch } = fakeFetch((c) => (c.path === '/auth/token/refresh' ? json(pair(fresh1, 'rt2')) : new Response(null, { status: 204 })));
    const auth = createJwtAuth({ baseUrl: 'https://api.example.com', mode: userSession({ storage, crossTab: false }), fetch });
    await auth.ready();
    storage.arm();
    const refreshing = auth.refresh().catch((e: unknown) => e);
    await storage.armed;
    const out = auth.logout();
    await flush();
    storage.release();
    await refreshing;
    await out;
    expect(auth.getState().status).toBe('anonymous');
    expect(await storage.get()).toEqual({ deviceId: 'd1' });
    expect(await auth.getAccessToken()).toBeNull();
  });

  it('switchCompany: a logout while the switch request is in flight is not undone', async () => {
    const storage = memoryStore();
    await storage.set({ accessToken: fresh1, refreshToken: 'rt1', expiresAt: now() + 900 });
    let releaseSwitch!: (r: Response) => void;
    const { fetch } = fakeFetch((c) =>
      c.path === '/auth/impersonate_in' ? new Promise<Response>((r) => (releaseSwitch = r)) : new Response(null, { status: 204 }),
    );
    const auth = createJwtAuth({
      baseUrl: 'https://api.example.com',
      endpoints: { switchCompany: '/auth/impersonate_in' },
      mode: userSession({ storage, crossTab: false }),
      fetch,
    });
    const switching = auth.switchCompany(5).catch((e: unknown) => e);
    await flush();
    await auth.logout();
    releaseSwitch(json(pair(fresh2, 'rt2')));
    const err = await switching;
    expect((err as SpAuthError).code).toBe('session_ended');
    expect(auth.getState().status).toBe('anonymous');
    expect(await storage.get()).toBeNull();
  });
});

describe('small correctness', () => {
  it('ensureDeviceId does not memoise a failure, and falls back to getRandomValues', async () => {
    const store = memoryStore();
    const real = globalThis.crypto;
    vi.stubGlobal('crypto', {});
    await expect(ensureDeviceId(store)).rejects.toThrow();
    vi.stubGlobal('crypto', { getRandomValues: (a: Uint8Array) => real.getRandomValues(a) });
    const id = await ensureDeviceId(store);
    expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    expect((await store.get())?.deviceId).toBe(id);
    expect(await ensureDeviceId(store)).toBe(id);
  });

  it('findTokenPair rejects an empty access token but tolerates a bad expires_in', () => {
    expect(findTokenPair({ access_token: '', expires_in: 900, token_type: 'Bearer' })).toBeNull();
    expect(findTokenPair({ access_token: 'a', expires_in: Number.NaN, token_type: 'Bearer' })?.expires_in).toBe(0);
    expect(findTokenPair({ access_token: 'a', expires_in: -1, token_type: 'Bearer' })?.expires_in).toBe(0);
    expect(findTokenPair({ access_token: 'a', expires_in: Number.POSITIVE_INFINITY, token_type: 'Bearer' })?.expires_in).toBe(0);
    expect(findTokenPair({ access_token: 'a', expires_in: 0, token_type: 'Bearer' })).not.toBeNull();
    expect(findTokenPair({ token: { access_token: 'a', expires_in: 900 } })).not.toBeNull();
  });

  it('a login answered with an empty access token does not authenticate', async () => {
    const { fetch } = fakeFetch(() => json({ access_token: '', refresh_token: 'rt', expires_in: 900, token_type: 'Bearer' }));
    const auth = createJwtAuth({ baseUrl: 'https://api.example.com', endpoints: { login: '/auth/login' }, mode: userSession(), fetch });
    expect((await caught(auth.login({}))).code).toBe('unknown');
    expect(auth.getState().status).toBe('anonymous');
  });

  it('social: a route without the :provider placeholder is not_configured, with no request', async () => {
    const { fetch, calls } = fakeFetch(() => json(pair(fresh1)));
    const auth: JwtAuth = createJwtAuth({
      baseUrl: 'https://api.example.com',
      endpoints: { socialRedirect: '/auth/google/redirect', socialCallback: '/auth/callback' },
      mode: userSession(),
      fetch,
    });
    const e1 = (() => {
      try {
        social(auth).redirectUrl('google');
      } catch (e) {
        return e as SpAuthError;
      }
      throw new Error('expected a throw');
    })();
    expect(e1.code).toBe('not_configured');
    expect(e1.module).toBe('social');
    const e2 = await caught(social(auth).completeFromCallback('google', { code: 'x' }));
    expect(e2.code).toBe('not_configured');
    expect(e2.module).toBe('social');
    expect(calls).toHaveLength(0);
  });
});
