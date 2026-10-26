/**
 * Message sent between tabs (spec §4.5 rule 3). `tokens` carries the ACCESS
 * token and its expiry (epoch seconds, `0` when unknown) only, never a refresh
 * token; `logout` says the shared session was cleared.
 */
export type TabMessage = { type: 'tokens'; accessToken: string; expiresAt: number } | { type: 'logout' };

/** Cross-tab coordination for one storage key. */
export interface CrossTab {
  /** Runs `fn` holding the refresh lock `sp-jwt-auth:refresh:<key>` (Web Locks, else an in-process mutex per key). */
  withLock<T>(fn: () => Promise<T>): Promise<T>;
  /** Tells other tabs (best effort; a no-op without `BroadcastChannel`). Only the documented fields are sent. */
  broadcast(m: TabMessage): void;
  /** Registers a listener for messages from other tabs; returns the unsubscribe function. Listener errors are swallowed. */
  onMessage(cb: (m: TabMessage) => void): () => void;
  /** The last token another tab broadcast (reset by a `logout` from anywhere), or `null`. */
  lastBroadcast(): { accessToken: string; expiresAt: number } | null;
  /** Removes every listener and closes the channel. `withLock` keeps working; `broadcast` becomes a no-op. */
  close(): void;
}

/** The part of the Web Locks `LockManager` that is used. */
export interface LockManagerLike {
  request(name: string, cb: () => Promise<unknown>): Promise<unknown>;
}

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

/** Promise-chain mutex: callers using the same `k` in `map` run one at a time. */
function exclusive<K, T>(map: ChainMap<K>, k: K, fn: () => Promise<T>): Promise<T> {
  const prev = map.get(k) ?? Promise.resolve();
  const run = prev.then(() => fn());
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
const mutex = <T>(name: string, fn: () => Promise<T>): Promise<T> => exclusive(named, name, fn);

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
    return { type: 'tokens', accessToken: d.accessToken, expiresAt };
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
  let last: { accessToken: string; expiresAt: number } | null = null;
  let closed = false;

  const deliver = (m: TabMessage | null): void => {
    if (closed || !m) return;
    last = m.type === 'tokens' ? { accessToken: m.accessToken, expiresAt: m.expiresAt } : null;
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
    withLock<T>(fn: () => Promise<T>): Promise<T> {
      if (!locks) return mutex(lockName, fn);
      let entered = false;
      let req: Promise<unknown>;
      try {
        req = locks.request(lockName, () => {
          entered = true;
          return fn();
        });
      } catch {
        return mutex(lockName, fn);
      }
      return Promise.resolve(req).then(
        (v) => v as T,
        (e: unknown) => {
          if (entered) throw e;
          return mutex(lockName, fn); // the lock could not be acquired: still serialise in-process
        },
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
