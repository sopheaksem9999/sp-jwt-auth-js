/** Persisted auth state. `expiresAt` is epoch SECONDS. */
export interface Tokens {
  accessToken?: string;
  refreshToken?: string;
  /** Access-token expiry, epoch seconds. */
  expiresAt?: number;
  csrf?: string;
  deviceId?: string;
  lastCompanyId?: string;
}

/**
 * Async token persistence. Implementations must never throw from `get`/`set`.
 * Logout convention: call `set(null)` to clear tokens, then re-store only
 * `{ deviceId }` so the device id survives logout.
 */
export interface TokenStore {
  get(): Promise<Tokens | null>;
  set(t: Tokens | null): Promise<void>;
  /**
   * Optional key identifying the shared storage location (set, non-enumerable,
   * by `webStorageStore`). `userSession` uses it to name the cross-tab lock and channel.
   */
  readonly storageKey?: string;
}

/** In-memory store; state is lost on reload. Safe on any runtime. */
export function memoryStore(): TokenStore {
  let current: Tokens | null = null;
  return {
    get: () => Promise.resolve(current ? { ...current } : null), // copies: callers cannot alias state
    set: (t) => {
      current = t ? { ...t } : null;
      return Promise.resolve();
    },
  };
}

type WebStorage = Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>;

function resolveStorage(kind: 'localStorage' | 'sessionStorage'): WebStorage | null {
  try {
    const s = (globalThis as Record<string, unknown>)[kind] as WebStorage | undefined | null;
    return s && typeof s.getItem === 'function' ? s : null;
  } catch {
    return null;
  }
}

/**
 * Store backed by `localStorage` or `sessionStorage` under `key`, as JSON.
 * Feature-detected on `globalThis`; every access is guarded, so blocked or
 * missing storage yields `get() -> null` and no-op writes. Corrupt JSON -> null.
 * `set(null)` removes the key. Exposes `key` as a non-enumerable `storageKey`.
 */
export function webStorageStore(kind: 'localStorage' | 'sessionStorage', key: string): TokenStore {
  const store: TokenStore = {
    get: () => {
      try {
        const raw = resolveStorage(kind)?.getItem(key);
        if (raw == null) return Promise.resolve(null);
        const v: unknown = JSON.parse(raw);
        return Promise.resolve(v !== null && typeof v === 'object' && !Array.isArray(v) ? (v as Tokens) : null);
      } catch {
        return Promise.resolve(null);
      }
    },
    set: (t) => {
      try {
        const s = resolveStorage(kind);
        if (s) {
          if (t === null) s.removeItem(key);
          else s.setItem(key, JSON.stringify(t));
        }
      } catch {
        /* storage blocked or full: render without it */
      }
      return Promise.resolve();
    },
  };
  // Non-enumerable so the store's shape (and any spread/serialisation of it) is unchanged.
  Object.defineProperty(store, 'storageKey', { value: key, enumerable: false });
  return store;
}

const deviceIds = new WeakMap<TokenStore, Promise<string>>();

async function safeGet(store: TokenStore): Promise<Tokens | null> {
  try {
    return await store.get();
  } catch {
    return null;
  }
}

/**
 * A random UUIDv4: `crypto.randomUUID()` where it exists (secure contexts), else built
 * from `crypto.getRandomValues` (available on insecure origins such as plain-http
 * intranet hosts). Throws when neither exists.
 */
function randomUuid(): string {
  const c = globalThis.crypto as Partial<Crypto> | undefined;
  if (typeof c?.randomUUID === 'function') return c.randomUUID();
  if (typeof c?.getRandomValues !== 'function') throw new Error('No Web Crypto random source available');
  const b = c.getRandomValues(new Uint8Array(16));
  b[6] = (b[6]! & 0x0f) | 0x40; // version 4
  b[8] = (b[8]! & 0x3f) | 0x80; // RFC 4122 variant
  const h = Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

async function resolveDeviceId(store: TokenStore): Promise<string> {
  const existing = (await safeGet(store))?.deviceId;
  if (existing) return existing;
  const generated = randomUuid();
  // Merge against a fresh read, not the earlier snapshot, so concurrent token writes are not clobbered.
  const fresh = await safeGet(store);
  if (fresh?.deviceId) return fresh.deviceId;
  try {
    await store.set({ ...(fresh ?? {}), deviceId: generated });
  } catch {
    /* not persisted; the per-store memo still keeps the id stable for this session */
  }
  return generated;
}

/**
 * Returns the persisted `deviceId`, or generates one with Web Crypto
 * (`crypto.randomUUID()`, else a UUIDv4 from `crypto.getRandomValues`), stores it
 * (other fields preserved, merged against a fresh read) and returns it. Concurrent
 * and repeat calls on the same store instance share one memoised id; a failure is
 * not memoised, so the next call tries again. The id is stable per store instance within a
 * session; stable across reloads only if the store persists. Logout clears
 * tokens but keeps `deviceId`: `set(null)` then `set({ deviceId })`.
 */
export function ensureDeviceId(store: TokenStore): Promise<string> {
  let p = deviceIds.get(store);
  if (!p) {
    const created = resolveDeviceId(store);
    p = created;
    deviceIds.set(store, created);
    created.catch(() => {
      if (deviceIds.get(store) === created) deviceIds.delete(store);
    });
  }
  return p;
}
