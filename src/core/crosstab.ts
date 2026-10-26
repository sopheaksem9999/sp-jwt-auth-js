/**
 * Message sent between tabs (spec §4.5 rule 3). `tokens` carries the ACCESS
 * token and its expiry (epoch seconds, `0` when unknown) only, never a refresh
 * token, plus (cookie transport only) the non-secret CSRF double-submit value;
 * `logout` says the shared session was cleared.
 */
export type TabMessage = { type: 'tokens'; accessToken: string; expiresAt: number; csrf?: string } | { type: 'logout' };

/** A token another tab broadcast (see `CrossTab.lastBroadcast`). */
export interface BroadcastToken {
  accessToken: string;
  /** Epoch seconds, `0` when unknown. */
  expiresAt: number;
  /** Cookie transport: the CSRF value that came with it. */
  csrf?: string;
}

/**
 * How the refresh lock was obtained, passed to the `withLock` callback.
 * `contended`: another holder had the lock when it was requested, so this
 * caller waited for it (that holder may just have rotated and broadcast). A
 * caller-supplied `CrossTab` may omit the argument; treat that as uncontended.
 */
export interface LockGrant {
  contended: boolean;
}

/** Cross-tab coordination for one storage key. */
export interface CrossTab {
  /**
   * Runs `fn` holding the refresh lock `sp-jwt-auth:refresh:<key>` (Web Locks, else an in-process mutex per key).
   * `fn` receives a `LockGrant` saying whether the lock was contended.
   */
  withLock<T>(fn: (grant?: LockGrant) => Promise<T>): Promise<T>;
  /** Tells other tabs (best effort; a no-op without `BroadcastChannel`). Only the documented fields are sent. */
  broadcast(m: TabMessage): void;
  /** Registers a listener for messages from other tabs; returns the unsubscribe function. Listener errors are swallowed. */
  onMessage(cb: (m: TabMessage) => void): () => void;
  /** The last token another tab broadcast (reset by a `logout` from anywhere), or `null`. */
  lastBroadcast(): BroadcastToken | null;
  /** Removes every listener and closes the channel. `withLock` keeps working; `broadcast` becomes a no-op. */
  close(): void;
}

/**
 * The part of the Web Locks `LockManager` that is used: `request(name, cb)`.
 * When the implementation also supports `request(name, { ifAvailable: true }, cb)`
 * (`cb` gets `null` while the lock is held), as `navigator.locks` does, that is
 * used first to tell a contended grant from a free one (see `LockGrant`). One
 * without the options form still works: the probe fails before `cb` runs and the
 * plain form is used, reported as uncontended.
 */
export interface LockManagerLike {
  request(name: string, cb: () => Promise<unknown>): Promise<unknown>;
}

/** `LockManagerLike` with the `ifAvailable` form, as the probe calls it (an implementation may lack it). */
type ProbingLocks = {
  request(name: string, options: { ifAvailable: boolean }, cb: (lock: unknown) => Promise<unknown>): Promise<unknown>;
};

/** Test and advanced seams for `createCrossTab`. `undefined` means feature-detect; `null` means "not available". */
export interface CrossTabDeps {
  /** Lock manager; default `globalThis.navigator.locks`. */
  locks?: LockManagerLike | null;
  /** Channel factory; default `new globalThis.BroadcastChannel(name)`. */
  channel?: ((name: string) => BroadcastChannel | null) | null;
  /** Target for the `storage` event fallback; default `globalThis` when it has `addEventListener`. */
  events?: Pick<EventTarget, 'addEventListener' | 'removeEventListener'> | null;
  /** Web-storage key watched by the `storage` fallback; default `key`, `null` turns the fallback off. */
  storageKey?: string | null;
}

type ChainMap<K> = { get(k: K): Promise<unknown> | undefined; set(k: K, v: Promise<unknown>): unknown; delete(k: K): unknown };

/** Promise-chain mutex: callers using the same `k` in `map` run one at a time (`contended` when one was queued or running). */
function exclusive<K, T>(map: ChainMap<K>, k: K, fn: (grant: LockGrant) => Promise<T>): Promise<T> {
  const held = map.get(k);
  const contended = held !== undefined;
  const run = (held ?? Promise.resolve()).then(() => fn({ contended }));
  const tail = run.then(
    () => undefined,
    () => undefined,
  );
  map.set(k, tail);
  void tail.then(() => {
    if (map.get(k) === tail) map.delete(k);
  });
  return run;
}

/** Named chains: shared by every `createCrossTab` with the same key in this process. */
const named = new Map<string, Promise<unknown>>();
const mutex = <T>(name: string, fn: (grant: LockGrant) => Promise<T>): Promise<T> => exclusive(named, name, fn);

/** Chains scoped to one store object (no string key, so unrelated sessions never share a lock). */
const scoped = new WeakMap<object, Promise<unknown>>();

/**
 * Local coordinator for a store with no cross-tab identity (memory or custom
 * store, no explicit key): an in-process mutex scoped to `scope` (the store
 * object), so instances over the SAME store serialise their refreshes, while
 * instances over different stores (e.g. per-request sessions on a server)
 * share nothing. No channel, no globals; `broadcast` is a no-op and
 * `lastBroadcast()` is always `null`.
 */
export function storeScopedCrossTab(scope: object): CrossTab {
  return {
    withLock: (fn) => exclusive(scoped, scope, fn),
    broadcast: () => undefined,
    onMessage: () => () => undefined,
    lastBroadcast: () => null,
    close: () => undefined,
  };
}

/** Probe result meaning "the lock is held by someone else". */
const HELD: unique symbol = Symbol('held');

function detectLocks(): LockManagerLike | null {
  try {
    const nav = (globalThis as { navigator?: { locks?: unknown } }).navigator;
    const locks = nav?.locks as LockManagerLike | undefined;
    return locks && typeof locks.request === 'function' ? locks : null;
  } catch {
    return null;
  }
}

function detectChannel(name: string): BroadcastChannel | null {
  try {
    const BC = (globalThis as { BroadcastChannel?: unknown }).BroadcastChannel;
    if (typeof BC !== 'function') return null;
    const ch = new (BC as typeof BroadcastChannel)(name);
    try {
      // Node: do not keep the process alive just for this channel.
      (ch as { unref?: () => void }).unref?.();
    } catch {
      /* not Node */
    }
    return ch;
  } catch {
    return null;
  }
}

function detectEvents(): Pick<EventTarget, 'addEventListener' | 'removeEventListener'> | null {
  try {
    const g = globalThis as { addEventListener?: unknown; removeEventListener?: unknown };
    return typeof g.addEventListener === 'function' && typeof g.removeEventListener === 'function'
      ? (globalThis as unknown as EventTarget)
      : null;
  } catch {
    return null;
  }
}

/** Validates untrusted data into a `TabMessage` holding only the documented fields. */
function sanitize(data: unknown): TabMessage | null {
  if (data === null || typeof data !== 'object') return null;
  const d = data as Record<string, unknown>;
  if (d.type === 'logout') return { type: 'logout' };
  if (d.type === 'tokens' && typeof d.accessToken === 'string' && d.accessToken !== '') {
    const expiresAt = typeof d.expiresAt === 'number' && Number.isFinite(d.expiresAt) ? d.expiresAt : 0;
    const m: TabMessage = { type: 'tokens', accessToken: d.accessToken, expiresAt };
    if (typeof d.csrf === 'string' && d.csrf !== '') m.csrf = d.csrf;
    return m;
  }
  return null;
}

function parseStored(raw: unknown): Record<string, unknown> | null {
  if (typeof raw !== 'string') return null;
  try {
    const v: unknown = JSON.parse(raw);
    return v !== null && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/** Maps a `storage` event on the token key to a message: a stored access token is `tokens`; one removed is `logout`. */
function fromStorageEvent(e: Event, watched: string): TabMessage | null {
  const { key, newValue, oldValue } = e as Event & { key?: unknown; newValue?: unknown; oldValue?: unknown };
  if (key === null) return { type: 'logout' }; // storage.clear()
  if (key !== watched) return null;
  const next = parseStored(newValue);
  if (next && typeof next.accessToken === 'string') {
    return sanitize({ type: 'tokens', accessToken: next.accessToken, expiresAt: next.expiresAt });
  }
  const prev = parseStored(oldValue);
  return prev && typeof prev.accessToken === 'string' ? { type: 'logout' } : null;
}

/**
 * Cross-tab coordination (spec §4.5 rule 3) for `key` (the storage key).
 *
 * - Lock: Web Locks `sp-jwt-auth:refresh:<key>` when `navigator.locks` exists.
 *   Without it, or when acquiring fails, an in-process mutex shared by every
 *   instance with the same key. An error thrown by `fn` is never retried.
 *   Web Locks are first asked with `ifAvailable`: a free lock is taken at once
 *   (`{ contended: false }`); a held one is then queued for (`{ contended: true }`).
 *   The mutex reports `contended` when another caller was queued or running.
 * - Messages: `BroadcastChannel('sp-jwt-auth:tabs:<key>')` when available,
 *   else the `storage` event on the watched web-storage key (where
 *   `addEventListener` exists), else nothing (edge/Node: `broadcast` is a no-op).
 *
 * `lastBroadcast()` is per instance and only ever filled from messages received
 * on this key's channel (or storage key). Every global is feature-detected and
 * guarded, and nothing is opened until the first `broadcast`/`onMessage`. Call
 * `close()` when the instance is no longer used.
 */
export function createCrossTab(key: string, deps: CrossTabDeps = {}): CrossTab {
  const lockName = `sp-jwt-auth:refresh:${key}`;
  const channelName = `sp-jwt-auth:tabs:${key}`;
  const listeners = new Set<(m: TabMessage) => void>();
  let last: BroadcastToken | null = null;
  let closed = false;

  const deliver = (m: TabMessage | null): void => {
    if (closed || !m) return;
    if (m.type === 'tokens') {
      last = { accessToken: m.accessToken, expiresAt: m.expiresAt };
      if (m.csrf !== undefined) last.csrf = m.csrf;
    } else last = null;
    for (const cb of [...listeners]) {
      try {
        cb(m);
      } catch {
        /* one listener must not break the others */
      }
    }
  };

  let channel: BroadcastChannel | null = null;
  let events: Pick<EventTarget, 'addEventListener' | 'removeEventListener'> | null = null;
  const onChannel = (e: Event): void => deliver(sanitize((e as MessageEvent).data));
  const watched = deps.storageKey === undefined ? key : deps.storageKey;
  const onStorage = (e: Event): void => {
    if (watched !== null) deliver(fromStorageEvent(e, watched));
  };

  // Opened lazily, on the first `broadcast` or `onMessage`: creating a CrossTab touches no globals.
  let opened = false;
  const open = (): void => {
    if (opened || closed) return;
    opened = true;
    try {
      if (deps.channel === undefined) channel = detectChannel(channelName);
      else if (deps.channel) channel = deps.channel(channelName);
    } catch {
      channel = null;
    }
    if (channel) {
      try {
        channel.addEventListener('message', onChannel);
      } catch {
        channel = null;
      }
    }
    if (!channel && watched !== null) {
      events = deps.events === undefined ? detectEvents() : deps.events;
      try {
        events?.addEventListener('storage', onStorage);
      } catch {
        events = null;
      }
    }
  };

  const locks = deps.locks === undefined ? detectLocks() : deps.locks;

  return {
    withLock<T>(fn: (grant: LockGrant) => Promise<T>): Promise<T> {
      if (!locks) return mutex(lockName, fn);
      let entered = false;
      const enter = (contended: boolean): Promise<T> => {
        entered = true;
        return fn({ contended });
      };
      // The lock could not be acquired at all: still serialise in-process.
      const degrade = (e: unknown): Promise<T> => {
        if (entered) throw e;
        return mutex(lockName, fn);
      };
      /** Waits in the queue: `contended` is `true` when the probe saw the lock held. */
      const queued = (contended: boolean): Promise<T> => {
        let req: Promise<unknown>;
        try {
          req = locks.request(lockName, () => enter(contended));
        } catch (e) {
          return degrade(e);
        }
        return Promise.resolve(req).then((v) => v as T, degrade);
      };
      // Probe first with `ifAvailable`: a free lock is taken at once (uncontended); a held one
      // answers `null` and we queue (contended). An implementation without the options form
      // fails the probe before entering, and is then asked the plain way.
      let probe: Promise<unknown>;
      try {
        probe = (locks as unknown as ProbingLocks).request(lockName, { ifAvailable: true }, (lock: unknown) =>
          lock === null ? Promise.resolve(HELD) : enter(false),
        );
      } catch {
        return queued(false);
      }
      return Promise.resolve(probe).then(
        (v) => (v === HELD ? queued(true) : (v as T)),
        (e: unknown) => (entered ? Promise.reject(e) : queued(false)),
      );
    },

    broadcast(m) {
      const clean = sanitize(m);
      if (!clean) return;
      if (clean.type === 'logout') last = null;
      open();
      if (closed || !channel) return;
      try {
        channel.postMessage(clean);
      } catch {
        /* closed or not cloneable: best effort */
      }
    },

    onMessage(cb) {
      if (closed) return () => undefined;
      open();
      listeners.add(cb);
      return () => {
        listeners.delete(cb);
      };
    },

    lastBroadcast: () => (last ? { ...last } : null),

    close() {
      if (closed) return;
      closed = true;
      listeners.clear();
      try {
        channel?.removeEventListener('message', onChannel);
        channel?.close();
      } catch {
        /* already closed */
      }
      try {
        events?.removeEventListener('storage', onStorage);
      } catch {
        /* ignore */
      }
      channel = null;
      events = null;
    },
  };
}

/** Result of `resolveSessionCrossTab`. */
export interface SessionCrossTab {
  crossTab: CrossTab | null;
  /** `true` when the session created it (and so closes it on dispose). */
  owned: boolean;
  /**
   * `true` when it has a real cross-tab identity: an explicit key (`true`,
   * `{ key }`), an injected `{ instance }`, or a `webStorageStore` key. `false`
   * for the store-scoped coordinator (memory or custom store) and for `false`.
   */
  named: boolean;
  /** `true` for an injected `{ instance }` (the caller vouches for its transport). */
  injected: boolean;
}

/**
 * Picks the coordinator for a `userSession` (see `UserSessionOptions.crossTab`).
 * ON by default only for a store with a `storageKey` (`webStorageStore`); a
 * memory or custom store gets a store-scoped in-process lock (no channel, no
 * globals), so per-request server sessions never share a lock or a token.
 */
export function resolveSessionCrossTab(
  option: boolean | { key?: string; instance?: CrossTab } | undefined,
  store: { readonly storageKey?: string } & object,
): SessionCrossTab {
  if (option === false) return { crossTab: null, owned: false, named: false, injected: false };
  if (typeof option === 'object' && option.instance) return { crossTab: option.instance, owned: false, named: true, injected: true };
  const explicitKey = typeof option === 'object' ? option.key : undefined;
  if (option === true || explicitKey !== undefined || store.storageKey !== undefined) {
    const key = explicitKey ?? store.storageKey ?? 'default';
    // The storage-event fallback only makes sense for a web-storage key.
    return { crossTab: createCrossTab(key, { storageKey: store.storageKey ?? null }), owned: true, named: true, injected: false };
  }
  return { crossTab: storeScopedCrossTab(store), owned: true, named: false, injected: false };
}
