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
    get: () => Promise.resolve(current ? { ...current } : null),
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

/**
 * Returns the persisted `deviceId`, or generates one with Web Crypto
 * (`crypto.randomUUID()`), stores it (other fields preserved) and returns it.
 * Repeat calls return the same id. Logout clears tokens but keeps `deviceId`:
 * `set(null)` then `set({ deviceId })`. If the store cannot persist, a fresh
 * in-memory id is returned, which is NOT stable across reloads.
 */
export async function ensureDeviceId(store: TokenStore): Promise<string> {
  let current: Tokens | null = null;
  try {
    current = await store.get();
  } catch {
    current = null;
  }
  if (current?.deviceId) return current.deviceId;
  const deviceId = globalThis.crypto.randomUUID();
  try {
    await store.set({ ...(current ?? {}), deviceId });
  } catch {
    /* not persisted; id valid for this call only */
  }
  return deviceId;
}
