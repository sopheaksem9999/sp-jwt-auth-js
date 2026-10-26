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
 * `set(null)` removes the key.
 */
export function webStorageStore(kind: 'localStorage' | 'sessionStorage', key: string): TokenStore {
  return {
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
}

const deviceIds = new WeakMap<TokenStore, Promise<string>>();

async function safeGet(store: TokenStore): Promise<Tokens | null> {
  try {
    return await store.get();
  } catch {
    return null;
  }
}

async function resolveDeviceId(store: TokenStore): Promise<string> {
  const existing = (await safeGet(store))?.deviceId;
  if (existing) return existing;
  const generated = globalThis.crypto.randomUUID();
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
 * (`crypto.randomUUID()`), stores it (other fields preserved, merged against a
 * fresh read) and returns it. Concurrent and repeat calls on the same store
 * instance share one memoised id. The id is stable per store instance within a
 * session; stable across reloads only if the store persists. Logout clears
 * tokens but keeps `deviceId`: `set(null)` then `set({ deviceId })`.
 */
export function ensureDeviceId(store: TokenStore): Promise<string> {
  let p = deviceIds.get(store);
  if (!p) {
    p = resolveDeviceId(store);
    deviceIds.set(store, p);
  }
  return p;
}
