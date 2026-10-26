import { afterEach, describe, expect, it, vi } from 'vitest';
import { createJwtAuth, userSession } from '../../src/core/create-jwt-auth';
import type { AuthEvent, JwtAuth, ModeContext } from '../../src/core/create-jwt-auth';
import { createCrossTab, storeScopedCrossTab } from '../../src/core/crosstab';
import type { CrossTab, TabMessage } from '../../src/core/crosstab';
import { performTokenRefresh } from '../../src/core/refresh';
import { memoryStore, webStorageStore } from '../../src/core/stores';
import type { TokenStore, Tokens } from '../../src/core/stores';
import * as api from '../../src/index';

function b64url(s: string): string {
  const bytes = new TextEncoder().encode(s);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function jwt(payload: Record<string, unknown>): string {
  return `${b64url(JSON.stringify({ alg: 'none', typ: 'JWT' }))}.${b64url(JSON.stringify(payload))}.sig`;
}

const now = (): number => Math.floor(Date.now() / 1000);

interface Deferred<T> {
  promise: Promise<T>;
  resolve(v: T): void;
}

function deferred<T>(): Deferred<T> {
  let resolve!: (v: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

/** Lets queued microtasks (fake channel delivery, store reads) run; no timers. */
async function flush(): Promise<void> {
  for (let i = 0; i < 30; i++) await Promise.resolve();
}

/** Spies standing in for `navigator.locks` and `BroadcastChannel`. */
function stubGlobals(): { locks: { request: ReturnType<typeof vi.fn> }; constructed: string[]; closed: number } {
  const out = {
    locks: { request: vi.fn((_n: string, a: unknown, b?: unknown) => ((typeof a === 'function' ? a : b) as LockCb)({})) },
    constructed: [] as string[],
    closed: 0,
  };
  vi.stubGlobal('navigator', { locks: out.locks });
  vi.stubGlobal(
    'BroadcastChannel',
    class {
      constructor(name: string) {
        out.constructed.push(name);
      }
      addEventListener(): void {}
      removeEventListener(): void {}
      postMessage(): void {}
      close(): void {
        out.closed++;
      }
    },
  );
  return out;
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

/** In-memory stand-in for `BroadcastChannel`: delivers to the other open channels of the same name on a microtask. */
class FakeBus {
  readonly open = new Set<FakeChannel>();
  readonly posted: unknown[] = [];
  readonly names: string[] = [];
  factory = (name: string): BroadcastChannel => {
    this.names.push(name);
    return new FakeChannel(this, name) as unknown as BroadcastChannel;
  };
}

class FakeChannel {
  readonly listeners = new Set<(e: { data: unknown }) => void>();
  closed = false;
  constructor(
    private readonly bus: FakeBus,
    readonly name: string,
  ) {
    bus.open.add(this);
  }
  addEventListener(type: string, l: (e: { data: unknown }) => void): void {
    if (type === 'message') this.listeners.add(l);
  }
  removeEventListener(type: string, l: (e: { data: unknown }) => void): void {
    if (type === 'message') this.listeners.delete(l);
  }
  postMessage(data: unknown): void {
    const wire = JSON.stringify(data);
    this.bus.posted.push(JSON.parse(wire));
    for (const c of this.bus.open) {
      if (c === this || c.name !== this.name) continue;
      queueMicrotask(() => {
        for (const l of [...c.listeners]) l({ data: JSON.parse(wire) });
      });
    }
  }
  close(): void {
    this.closed = true;
    this.bus.open.delete(this);
  }
}

type LockCb = (lock: unknown) => Promise<unknown>;

/**
 * Exclusive fake lock manager (one holder per name, FIFO), recording every request
 * (`name?` for an `ifAvailable` probe). Like `navigator.locks`, a probe gets `null`
 * while the lock is held or queued for.
 */
function fakeLocks(): { request(name: string, a: LockCb | { ifAvailable?: boolean }, b?: LockCb): Promise<unknown>; log: string[] } {
  const tails = new Map<string, Promise<unknown>>();
  const busy = new Map<string, number>();
  const log: string[] = [];
  return {
    log,
    request(name, a, b) {
      const cb = (typeof a === 'function' ? a : b)!;
      const probe = typeof a === 'object' && a.ifAvailable === true;
      log.push(probe ? `${name}?` : name);
      if (probe && (busy.get(name) ?? 0) > 0) return Promise.resolve().then(() => cb(null));
      busy.set(name, (busy.get(name) ?? 0) + 1);
      const run = (tails.get(name) ?? Promise.resolve()).then(() => cb({ name }));
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

const access1 = jwt({ sub: '7', exp: now() + 30 });
const access2 = jwt({ sub: '7', exp: now() + 900 });
const access3 = jwt({ sub: '7', exp: now() + 1800, company_id: 9 });
const RT1 = 'rt-secret-one';
const RT2 = 'rt-secret-two';
const RT3 = 'rt-secret-three';
const pair2 = { access_token: access2, refresh_token: RT2, expires_in: 900, token_type: 'Bearer' };
const nearExpiry = (): Tokens => ({ accessToken: access1, refreshToken: RT1, expiresAt: now() + 30, deviceId: 'd1' });

interface Tab {
  auth: JwtAuth;
  crossTab: CrossTab;
  events: AuthEvent[];
}

const opened: CrossTab[] = [];
afterEach(() => {
  for (const c of opened.splice(0)) c.close();
  vi.unstubAllGlobals();
});

function tab(store: TokenStore, fetch: typeof globalThis.fetch, deps: Parameters<typeof createCrossTab>[1]): Tab {
  const crossTab = createCrossTab('k', deps);
  opened.push(crossTab);
  const events: AuthEvent[] = [];
  const auth = createJwtAuth({
    baseUrl: 'https://api.test/api',
    endpoints: { login: '/auth/login', logout: '/auth/logout' },
    mode: userSession({ storage: store, crossTab: { instance: crossTab } }),
    fetch,
    onEvent: (e) => events.push(e),
  });
  return { auth, crossTab, events };
}

describe('two instances sharing a store (two tabs)', () => {
  it('both at expiry: exactly one refresh request; the second re-reads the store inside the lock and adopts the pair', async () => {
    const store = memoryStore();
    await store.set(nearExpiry());
    const bus = new FakeBus();
    const locks = fakeLocks();
    const calls: string[] = [];
    const fetch = (async (url: RequestInfo | URL) => {
      calls.push(String(url));
      return json(pair2);
    }) as typeof globalThis.fetch;
    const a = tab(store, fetch, { locks, channel: bus.factory, events: null });
    const b = tab(store, fetch, { locks, channel: bus.factory, events: null });
    await Promise.all([a.auth.ready(), b.auth.ready()]);

    const [ta, tb] = await Promise.all([a.auth.getAccessToken(), b.auth.getAccessToken()]);

    expect(ta).toBe(access2);
    expect(tb).toBe(access2);
    expect(calls).toHaveLength(1);
    expect(locks.log).toEqual(['sp-jwt-auth:refresh:k?', 'sp-jwt-auth:refresh:k?', 'sp-jwt-auth:refresh:k']);
    expect((await store.get())?.refreshToken).toBe(RT2);
    expect(a.events).toEqual([{ type: 'refresh' }]);
    expect(b.events).toEqual([{ type: 'refresh', adopted: true }]);
    expect(b.auth.getState().status).toBe('authenticated');
    expect(b.auth.getState().claims?.exp).toBe(JSON.parse(atob(access2.split('.')[1]!)).exp);
  });

  it('after one instance logs out, the other becomes anonymous via the broadcast (no request)', async () => {
    const store = memoryStore();
    await store.set({ accessToken: access2, refreshToken: RT2, expiresAt: now() + 900, deviceId: 'd1' });
    const bus = new FakeBus();
    const calls: string[] = [];
    const fetch = (async (url: RequestInfo | URL) => {
      calls.push(String(url));
      return new Response(null, { status: 204 });
    }) as typeof globalThis.fetch;
    const a = tab(store, fetch, { locks: fakeLocks(), channel: bus.factory, events: null });
    const b = tab(store, fetch, { locks: fakeLocks(), channel: bus.factory, events: null });
    await Promise.all([a.auth.ready(), b.auth.ready()]);
    expect(b.auth.getState().status).toBe('authenticated');
    const seen: string[] = [];
    b.auth.subscribe(() => seen.push(b.auth.getState().status));

    await a.auth.logout();
    await flush();

    expect(b.auth.getState().status).toBe('anonymous');
    expect(seen).toEqual(['anonymous']);
    expect(calls).toEqual(['https://api.test/api/auth/logout']); // only a's remote logout
    expect(await store.get()).toEqual({ deviceId: 'd1' });
    expect(bus.posted).toContainEqual({ type: 'logout' });
  });

  it('a login in one instance makes the other authenticated via the broadcast', async () => {
    const store = memoryStore();
    const bus = new FakeBus();
    const fetch = (async () => json(pair2)) as typeof globalThis.fetch;
    const a = tab(store, fetch, { locks: fakeLocks(), channel: bus.factory, events: null });
    const b = tab(store, fetch, { locks: fakeLocks(), channel: bus.factory, events: null });
    await Promise.all([a.auth.ready(), b.auth.ready()]);
    expect(b.auth.getState().status).toBe('anonymous');

    await a.auth.login({ email: 'e', password: 'p' });
    await flush();

    expect(b.auth.getState().status).toBe('authenticated');
    expect(b.crossTab.lastBroadcast()).toEqual({ accessToken: access2, expiresAt: expect.any(Number) });
  });

  it('broadcast payloads never contain a refresh token', async () => {
    const store = memoryStore();
    await store.set(nearExpiry());
    const bus = new FakeBus();
    const fetch = (async (url: RequestInfo | URL) =>
      String(url).endsWith('/auth/token/refresh') ? json(pair2) : json({ ...pair2, refresh_token: RT3 })) as typeof globalThis.fetch;
    const a = tab(store, fetch, { locks: fakeLocks(), channel: bus.factory, events: null });
    tab(store, fetch, { locks: fakeLocks(), channel: bus.factory, events: null });
    await a.auth.refresh();
    await a.auth.login({});
    await a.auth.logout();
    await flush();

    const wire = JSON.stringify(bus.posted);
    expect(bus.posted.length).toBeGreaterThanOrEqual(3);
    for (const secret of [RT1, RT2, RT3, 'refresh']) expect(wire).not.toContain(secret);
    for (const m of bus.posted as Record<string, unknown>[]) {
      expect(Object.keys(m).sort()).toEqual(m.type === 'tokens' ? ['accessToken', 'expiresAt', 'type'] : ['type']);
    }
  });

  it('crossTab: false disables the lock and the broadcast; true / key / webStorageStore turn it on, lazily', async () => {
    const g = stubGlobals();
    const store = memoryStore();
    await store.set(nearExpiry());
    const off = createJwtAuth({
      baseUrl: 'https://api.test/api',
      endpoints: {},
      mode: userSession({ storage: store, crossTab: false }),
      fetch: (async () => json(pair2)) as typeof globalThis.fetch,
    });
    await off.refresh();
    expect(g.locks.request).not.toHaveBeenCalled();
    expect(g.constructed).toEqual([]);

    // Explicit `true` without a store key: 'default'. Nothing opens before first use.
    await store.set(nearExpiry());
    const on = createJwtAuth({
      baseUrl: 'https://api.test/api',
      endpoints: {},
      mode: userSession({ storage: store, crossTab: true }),
      fetch: (async () => json(pair2)) as typeof globalThis.fetch,
    });
    expect(g.constructed).toEqual([]);
    await on.refresh();
    expect(g.locks.request).toHaveBeenCalledWith('sp-jwt-auth:refresh:default', { ifAvailable: true }, expect.any(Function));
    expect(g.constructed).toEqual(['sp-jwt-auth:tabs:default']);

    // webStorageStore: default ON, named after its key; `{ key }` overrides.
    const web = createJwtAuth({ baseUrl: 'https://api.test', endpoints: {}, mode: userSession({ storage: webStorageStore('localStorage', 'app.auth') }) });
    const custom = createJwtAuth({ baseUrl: 'https://api.test', endpoints: {}, mode: userSession({ storage: memoryStore(), crossTab: { key: 'custom' } }) });
    expect(g.constructed).toHaveLength(1); // lazy: created, not used yet
    await web.ready();
    await custom.ready();
    expect(g.constructed.slice(1)).toEqual(['sp-jwt-auth:tabs:app.auth', 'sp-jwt-auth:tabs:custom']);
    for (const a of [on, web, custom]) a.dispose?.();
    expect(g.closed).toBe(3);
  });
});

describe('default for memory / custom stores (servers, SSR)', () => {
  it('per-request sessions over memory stores open no channel and touch no navigator.locks', async () => {
    const g = stubGlobals();
    for (let i = 0; i < 3; i++) {
      const store = memoryStore();
      const auth = createJwtAuth({
        baseUrl: 'https://api.test/api',
        endpoints: { login: '/auth/login' },
        mode: userSession({ storage: store }),
        fetch: (async (url: RequestInfo | URL) =>
          String(url).endsWith('/auth/login') ? json({ ...pair2, access_token: access1 }) : json(pair2)) as typeof globalThis.fetch,
      });
      await auth.login({});
      expect(await auth.getAccessToken()).toBe(access2); // near expiry -> refresh
      await auth.logout();
    }
    expect(g.constructed).toEqual([]);
    expect(g.locks.request).not.toHaveBeenCalled();
  });

  it('two instances over ONE memory store still make one refresh request at expiry', async () => {
    const store = memoryStore();
    await store.set(nearExpiry());
    let calls = 0;
    const fetch = (async () => {
      calls++;
      return json(pair2);
    }) as typeof globalThis.fetch;
    const events: AuthEvent[] = [];
    const mk = (): JwtAuth =>
      createJwtAuth({ baseUrl: 'https://api.test/api', endpoints: {}, mode: userSession({ storage: store }), fetch, onEvent: (e) => events.push(e) });
    const [a, b] = [mk(), mk()];
    expect(await Promise.all([a.getAccessToken(), b.getAccessToken()])).toEqual([access2, access2]);
    expect(calls).toBe(1);
    expect(events).toEqual([{ type: 'refresh' }, { type: 'refresh', adopted: true }]);
  });

  it('instances over DIFFERENT memory stores neither serialise nor share anything', async () => {
    const gate = deferred<void>();
    const mk = (blocked: boolean): Promise<JwtAuth> => {
      const store = memoryStore();
      return store.set(nearExpiry()).then(() =>
        createJwtAuth({
          baseUrl: 'https://api.test/api',
          endpoints: {},
          mode: userSession({ storage: store }),
          fetch: (async () => {
            if (blocked) await gate.promise;
            return json(pair2);
          }) as typeof globalThis.fetch,
        }),
      );
    };
    const a = await mk(true);
    const b = await mk(false);
    const pa = a.getAccessToken();
    await flush();
    // a's refresh is stuck in flight; b must not wait for it.
    expect(await b.getAccessToken()).toBe(access2);
    gate.resolve();
    expect(await pa).toBe(access2);

    // The store-scoped coordinator never shares messages or lastBroadcast.
    const s1 = storeScopedCrossTab(memoryStore());
    const s2 = storeScopedCrossTab(memoryStore());
    const got: TabMessage[] = [];
    s2.onMessage((m) => got.push(m));
    s1.broadcast({ type: 'tokens', accessToken: 'x', expiresAt: now() + 900 });
    await flush();
    expect(got).toEqual([]);
    expect(s1.lastBroadcast()).toBeNull();
    expect(s2.lastBroadcast()).toBeNull();
  });
});

describe('reuse suspected', () => {
  it('a refresh 401 after another tab rotated adopts the stored tokens, emits reuse_suspected and keeps the session', async () => {
    const store = memoryStore();
    await store.set(nearExpiry());
    const gate = deferred<void>();
    const fetch = (async () => {
      await gate.promise;
      return json({ message: 'Refresh token reused' }, 401);
    }) as typeof globalThis.fetch;
    const a = tab(store, fetch, { locks: fakeLocks(), channel: null, events: null });
    await a.auth.ready();
    const h = a.auth.handleUnauthorized();
    await flush();
    // Another tab (without a shared lock) rotated meanwhile.
    await store.set({ accessToken: access3, refreshToken: RT3, expiresAt: now() + 1800, deviceId: 'd1' });
    gate.resolve();

    expect(await h).toBe(true);
    expect(await store.get()).toEqual({ accessToken: access3, refreshToken: RT3, expiresAt: expect.any(Number), deviceId: 'd1' });
    expect(a.auth.getState().status).toBe('authenticated');
    expect(a.auth.getState().companyId).toBe('9');
    expect(a.events).toEqual([{ type: 'reuse_suspected', status: 401 }]); // not refresh_failed as well
    const wire = JSON.stringify(a.events);
    for (const secret of [RT1, RT3, access1, access3]) expect(wire).not.toContain(secret);
    expect(await a.auth.getAccessToken()).toBe(access3);
  });

  it('a refresh 401 where the store has a newer refresh token but no access token ends the session', async () => {
    const store = memoryStore();
    await store.set(nearExpiry());
    const gate = deferred<void>();
    const fetch = (async () => {
      await gate.promise;
      return json({}, 401);
    }) as typeof globalThis.fetch;
    const a = tab(store, fetch, { locks: fakeLocks(), channel: null, events: null });
    await a.auth.ready();
    const h = a.auth.handleUnauthorized();
    await flush();
    await store.set({ refreshToken: RT3, deviceId: 'd1' });
    gate.resolve();
    expect(await h).toBe(false);
    expect(a.events.map((e) => e.type)).toEqual(['refresh_failed', 'session_ended']);
    expect(a.auth.getState().status).toBe('anonymous');
    expect(await store.get()).toEqual({ deviceId: 'd1' });
  });

  it('a refresh 401 with the store unchanged still ends the session', async () => {
    const store = memoryStore();
    await store.set(nearExpiry());
    const a = tab(store, (async () => json({}, 401)) as typeof globalThis.fetch, { locks: fakeLocks(), channel: null, events: null });
    expect(await a.auth.handleUnauthorized()).toBe(false);
    expect(a.events.map((e) => e.type)).toEqual(['refresh_failed', 'session_ended']);
    expect(await store.get()).toEqual({ deviceId: 'd1' });
  });
});

describe('createCrossTab', () => {
  it('withLock goes through the lock manager under sp-jwt-auth:refresh:<key> and is exclusive', async () => {
    const locks = fakeLocks();
    const ct = createCrossTab('k', { locks, channel: null, events: null });
    opened.push(ct);
    const gate = deferred<void>();
    const order: string[] = [];
    const first = ct.withLock(async () => {
      order.push('a:start');
      await gate.promise;
      order.push('a:end');
      return 1;
    });
    const second = ct.withLock(async () => {
      order.push('b:start');
      return 2;
    });
    await flush();
    expect(order).toEqual(['a:start']);
    gate.resolve();
    expect(await Promise.all([first, second])).toEqual([1, 2]);
    expect(order).toEqual(['a:start', 'a:end', 'b:start']);
    expect(locks.log).toEqual(['sp-jwt-auth:refresh:k?', 'sp-jwt-auth:refresh:k?', 'sp-jwt-auth:refresh:k']);
  });

  it('withLock reports contention: a free lock is uncontended, one taken while held is contended', async () => {
    const locks = fakeLocks();
    const a = createCrossTab('k', { locks, channel: null, events: null });
    const b = createCrossTab('k', { locks, channel: null, events: null });
    opened.push(a, b);
    const gate = deferred<void>();
    const grants: unknown[] = [];
    const first = a.withLock(async (g) => {
      grants.push(['a', g]);
      await gate.promise;
    });
    await flush();
    const second = b.withLock(async (g) => {
      grants.push(['b', g]);
    });
    await flush();
    gate.resolve();
    await Promise.all([first, second]);
    expect(grants).toEqual([
      ['a', { contended: false }],
      ['b', { contended: true }],
    ]);
    expect(await a.withLock(async (g) => g)).toEqual({ contended: false });
  });

  it('a lock manager without the ifAvailable form still serialises (reported uncontended)', async () => {
    const tails = new Map<string, Promise<unknown>>();
    const plain = {
      request(name: string, cb: () => Promise<unknown>): Promise<unknown> {
        const run = (tails.get(name) ?? Promise.resolve()).then(() => cb());
        tails.set(
          name,
          run.catch(() => undefined),
        );
        return run;
      },
    };
    const ct = createCrossTab('plain', { locks: plain, channel: null, events: null });
    opened.push(ct);
    const gate = deferred<void>();
    const order: unknown[] = [];
    const first = ct.withLock(async (g) => {
      order.push(['a', g]);
      await gate.promise;
    });
    const second = ct.withLock(async (g) => {
      order.push(['b', g]);
    });
    await flush();
    expect(order).toEqual([['a', { contended: false }]]);
    gate.resolve();
    await Promise.all([first, second]);
    expect(order).toEqual([
      ['a', { contended: false }],
      ['b', { contended: false }],
    ]);
  });

  it('the in-process mutex and the store-scoped lock report contention too', async () => {
    for (const [a, b] of [
      [createCrossTab('mutex-grant', { locks: null, channel: null, events: null }), createCrossTab('mutex-grant', { locks: null, channel: null, events: null })],
      (() => {
        const scope = {};
        return [storeScopedCrossTab(scope), storeScopedCrossTab(scope)];
      })(),
    ] as [CrossTab, CrossTab][]) {
      const gate = deferred<void>();
      const grants: unknown[] = [];
      const first = a.withLock(async (g) => {
        grants.push(g);
        await gate.promise;
      });
      const second = b.withLock(async (g) => {
        grants.push(g);
      });
      await flush();
      gate.resolve();
      await Promise.all([first, second]);
      expect(grants).toEqual([{ contended: false }, { contended: true }]);
      a.close();
      b.close();
    }
  });

  it('a lock-acquire failure degrades to the in-process mutex instead of failing', async () => {
    const rejecting = { request: () => Promise.reject(new Error('SecurityError')) };
    const throwing = {
      request: (): Promise<unknown> => {
        throw new Error('boom');
      },
    };
    const a = createCrossTab('mutex-key', { locks: rejecting, channel: null, events: null });
    const b = createCrossTab('mutex-key', { locks: rejecting, channel: null, events: null });
    const c = createCrossTab('mutex-key-2', { locks: throwing, channel: null, events: null });
    opened.push(a, b, c);
    expect(await c.withLock(async () => 'sync-throw falls back too')).toBe('sync-throw falls back too');
    const gate = deferred<void>();
    const order: string[] = [];
    const first = a.withLock(async () => {
      order.push('a:start');
      await gate.promise;
      order.push('a:end');
      return 'a';
    });
    const second = b.withLock(async () => {
      order.push('b:start');
      return 'b';
    });
    await flush();
    expect(order).toEqual(['a:start']); // same key: serialised across instances
    gate.resolve();
    expect(await Promise.all([first, second])).toEqual(['a', 'b']);
    expect(order).toEqual(['a:start', 'a:end', 'b:start']);
  });

  it('an error thrown inside the lock propagates and is not retried', async () => {
    const locks = fakeLocks();
    const ct = createCrossTab('k', { locks, channel: null, events: null });
    opened.push(ct);
    const fn = vi.fn(async () => {
      throw new Error('inside');
    });
    await expect(ct.withLock(fn)).rejects.toThrow('inside');
    expect(fn).toHaveBeenCalledTimes(1);
    expect(await ct.withLock(async () => 'next')).toBe('next');
  });

  it('works without navigator or BroadcastChannel (edge / Node): in-process mutex, no-op broadcast', async () => {
    vi.stubGlobal('navigator', undefined);
    vi.stubGlobal('BroadcastChannel', undefined);
    const a = createCrossTab('edge-key');
    const b = createCrossTab('edge-key');
    opened.push(a, b);
    const got: TabMessage[] = [];
    b.onMessage((m) => got.push(m));
    const gate = deferred<void>();
    const order: string[] = [];
    const first = a.withLock(async () => {
      order.push('a');
      await gate.promise;
    });
    const second = b.withLock(async () => {
      order.push('b');
    });
    await flush();
    expect(order).toEqual(['a']);
    gate.resolve();
    await Promise.all([first, second]);
    expect(order).toEqual(['a', 'b']);
    expect(() => a.broadcast({ type: 'logout' })).not.toThrow();
    await flush();
    expect(got).toEqual([]);
    expect(a.lastBroadcast()).toBeNull();

    // And a whole session refreshes fine with the defaults in that runtime.
    const store = memoryStore();
    await store.set(nearExpiry());
    const auth = createJwtAuth({
      baseUrl: 'https://api.test/api',
      endpoints: {},
      mode: userSession({ storage: store }),
      fetch: (async () => json(pair2)) as typeof globalThis.fetch,
    });
    expect(await auth.getAccessToken()).toBe(access2);
  });

  it('delivers sanitised messages to other instances, tracks lastBroadcast, and strips extra fields', async () => {
    const bus = new FakeBus();
    const a = createCrossTab('k', { locks: null, channel: bus.factory, events: null });
    const b = createCrossTab('k', { locks: null, channel: bus.factory, events: null });
    opened.push(a, b);
    expect(bus.names).toEqual([]); // lazy: nothing opened at creation
    const got: TabMessage[] = [];
    b.onMessage((m) => got.push(m));
    expect(bus.names).toEqual(['sp-jwt-auth:tabs:k']);

    a.broadcast({ type: 'tokens', accessToken: 'at', expiresAt: 123, refreshToken: RT1 } as unknown as TabMessage);
    await flush();
    expect(bus.posted).toEqual([{ type: 'tokens', accessToken: 'at', expiresAt: 123 }]);
    expect(got).toEqual([{ type: 'tokens', accessToken: 'at', expiresAt: 123 }]);
    expect(b.lastBroadcast()).toEqual({ accessToken: 'at', expiresAt: 123 });
    expect(a.lastBroadcast()).toBeNull(); // own broadcasts are not "another tab's"

    a.broadcast({ type: 'logout' });
    await flush();
    expect(got[1]).toEqual({ type: 'logout' });
    expect(b.lastBroadcast()).toBeNull();

    // Malformed data from the channel is ignored.
    for (const ch of bus.open) {
      if (ch.name === 'sp-jwt-auth:tabs:k') for (const l of [...ch.listeners]) l({ data: { type: 'tokens', accessToken: 5 } });
    }
    expect(got).toHaveLength(2);
  });

  it('lastBroadcast is filled only from the same key\'s channel', async () => {
    const bus = new FakeBus();
    const a = createCrossTab('k1', { locks: null, channel: bus.factory, events: null });
    const b = createCrossTab('k2', { locks: null, channel: bus.factory, events: null });
    opened.push(a, b);
    b.onMessage(() => undefined);
    a.broadcast({ type: 'tokens', accessToken: 'at', expiresAt: 1 });
    await flush();
    expect(b.lastBroadcast()).toBeNull();
  });

  it('a throwing listener does not break the others', async () => {
    const bus = new FakeBus();
    const a = createCrossTab('k', { locks: null, channel: bus.factory, events: null });
    const b = createCrossTab('k', { locks: null, channel: bus.factory, events: null });
    opened.push(a, b);
    const got: TabMessage[] = [];
    b.onMessage(() => {
      throw new Error('bad listener');
    });
    b.onMessage((m) => got.push(m));
    a.broadcast({ type: 'logout' });
    await flush();
    expect(got).toEqual([{ type: 'logout' }]);
  });

  it('unsubscribe and close() remove listeners and close the channel', async () => {
    const bus = new FakeBus();
    const target = new EventTarget();
    const a = createCrossTab('k', { locks: null, channel: bus.factory, events: target });
    const b = createCrossTab('k', { locks: null, channel: bus.factory, events: target });
    opened.push(a);
    const got: TabMessage[] = [];
    const off = b.onMessage((m) => got.push(m));
    off();
    b.onMessage((m) => got.push(m));
    const bChannel = [...bus.open][0]!;
    b.close();
    expect(bChannel.closed).toBe(true);
    expect(bChannel.listeners.size).toBe(0);
    expect(bus.open.size).toBe(0);
    a.broadcast({ type: 'logout' });
    await flush();
    expect(got).toEqual([]);
    expect(() => b.broadcast({ type: 'logout' })).not.toThrow();
  });

  it('falls back to the storage event (on the store key) when there is no BroadcastChannel', async () => {
    const target = new EventTarget();
    const ct = createCrossTab('k', { locks: null, channel: null, events: target, storageKey: 'app.auth' });
    opened.push(ct);
    const got: TabMessage[] = [];
    ct.onMessage((m) => got.push(m));
    const fire = (key: string | null, newValue: string | null, oldValue: string | null): void => {
      target.dispatchEvent(Object.assign(new Event('storage'), { key, newValue, oldValue }));
    };
    const stored = JSON.stringify({ accessToken: 'at2', refreshToken: RT2, expiresAt: 77 });
    fire('other', stored, null); // another key: ignored
    fire('app.auth', stored, null);
    fire('app.auth', JSON.stringify({ deviceId: 'd1' }), stored);
    fire('app.auth', JSON.stringify({ deviceId: 'd1' }), null); // no token before or after: ignored
    expect(got).toEqual([{ type: 'tokens', accessToken: 'at2', expiresAt: 77 }, { type: 'logout' }]);
    expect(JSON.stringify(got)).not.toContain(RT2);

    ct.close();
    fire('app.auth', stored, null);
    expect(got).toHaveLength(2);
  });
});

describe('dispose', () => {
  it('JwtAuth.dispose() removes the subscription and closes an owned channel; an injected instance is only unsubscribed', async () => {
    const bus = new FakeBus();
    const injected = createCrossTab('k', { locks: null, channel: bus.factory, events: null });
    opened.push(injected);
    const store = memoryStore();
    const auth = createJwtAuth({
      baseUrl: 'https://api.test',
      endpoints: {},
      mode: userSession({ storage: store, crossTab: { instance: injected } }),
    });
    expect(bus.names).toEqual([]);
    await auth.ready(); // first use subscribes
    const ch = [...bus.open][0]!;
    expect(ch.listeners.size).toBe(1);
    auth.dispose?.();
    auth.dispose?.(); // idempotent
    expect(ch.closed).toBe(false); // the caller owns the injected instance
    // A message no longer reaches the disposed session.
    const other = createCrossTab('k', { locks: null, channel: bus.factory, events: null });
    opened.push(other);
    await store.set({ accessToken: access2, refreshToken: RT2 });
    other.broadcast({ type: 'tokens', accessToken: access2, expiresAt: 0 });
    await flush();
    expect(auth.getState().status).toBe('anonymous');

    const g = stubGlobals();
    const owned = createJwtAuth({ baseUrl: 'https://api.test', endpoints: {}, mode: userSession({ storage: memoryStore(), crossTab: { key: 'x' } }) });
    await owned.ready();
    owned.dispose?.();
    expect(g.constructed).toEqual(['sp-jwt-auth:tabs:x']);
    expect(g.closed).toBe(1);
  });
});

describe('cookie-transport seam: useBroadcastedToken', () => {
  function stubCtx(emitted: AuthEvent[], http: () => Promise<never>): ModeContext {
    return {
      options: { baseUrl: 'https://api.test', endpoints: {}, mode: { kind: 'x', create: () => ({}) as never } },
      http,
      endpoint: () => '/auth/token/refresh',
      emit: (e: AuthEvent) => emitted.push(e),
      now,
      setAuthenticated: () => undefined,
      setAnonymous: () => undefined,
    } as unknown as ModeContext;
  }

  it('inside the lock, a fresh token broadcast by another tab is used instead of refreshing', async () => {
    const fresh = { accessToken: 'at-b', expiresAt: now() + 600 };
    const crossTab: CrossTab = {
      withLock: (fn) => fn(),
      broadcast: () => undefined,
      onMessage: () => () => undefined,
      lastBroadcast: () => fresh,
      close: () => undefined,
    };
    const emitted: AuthEvent[] = [];
    const http = vi.fn(async () => {
      throw new Error('no request expected');
    });
    const used: unknown[] = [];
    const perform = performTokenRefresh({
      ctx: stubCtx(emitted, http),
      store: memoryStore(),
      clearSession: async () => undefined,
      crossTab,
      useBroadcastedToken: (b) => used.push(b),
    });
    await perform();
    expect(used).toEqual([fresh]);
    expect(http).not.toHaveBeenCalled();
    expect(emitted).toEqual([{ type: 'refresh', adopted: true }]);
  });

  it('a stale broadcast is not used', async () => {
    const crossTab: CrossTab = {
      withLock: (fn) => fn(),
      broadcast: () => undefined,
      onMessage: () => () => undefined,
      lastBroadcast: () => ({ accessToken: 'old', expiresAt: now() + 5 }),
      close: () => undefined,
    };
    const used: unknown[] = [];
    const perform = performTokenRefresh({
      ctx: stubCtx([], async () => {
        throw new Error('x');
      }),
      store: memoryStore(),
      clearSession: async () => undefined,
      crossTab,
      useBroadcastedToken: (b) => used.push(b),
    });
    await expect(perform()).rejects.toMatchObject({ code: 'session_ended' });
    expect(used).toEqual([]);
  });
});

describe('exports', () => {
  it('exposes createCrossTab from the package root, and webStorageStore carries a non-enumerable storageKey', () => {
    expect(api.createCrossTab).toBe(createCrossTab);
    const s = webStorageStore('localStorage', 'app.auth');
    expect(s.storageKey).toBe('app.auth');
    expect(Object.keys(s)).toEqual(['get', 'set']);
  });
});
