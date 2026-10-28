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

/**
 * Minimal string key-value storage seam; a superset of `localStorage`, so it drops in.
 * May be async (e.g. a native secure keychain wrapper). Removing an absent key must not throw.
 */
export interface KeyValueStorage {
  getItem(key: string): string | null | Promise<string | null>;
  setItem(key: string, value: string): void | Promise<void>;
  removeItem(key: string): void | Promise<void>;
}

/** Key names used by `keyValueTokenStore`; override to read a session persisted under other names. */
export interface StorageKeys {
  accessToken: string;
  refreshToken: string;
  expiresAt: string;
  csrf: string;
  deviceId: string;
  lastCompanyId: string;
}

const DEFAULT_KEYS: StorageKeys = {
  accessToken: 'sp_access_token',
  refreshToken: 'sp_refresh_token',
  expiresAt: 'sp_access_token_expires_at',
  csrf: 'sp_csrf',
  deviceId: 'sp_device_id',
  lastCompanyId: 'sp_last_company_id',
};

function parseExpiry(raw: string | null): number | undefined {
  const text = raw?.trim();
  if (!text) return undefined;
  const n = /^-?\d+(\.\d+)?$/.test(text) ? Number(text) : Date.parse(text) / 1000;
  return Number.isFinite(n) ? n : undefined;
}

function isWebStorage(storage: KeyValueStorage): boolean {
  return (['localStorage', 'sessionStorage'] as const).some((k) => resolveStorage(k) === storage);
}

/**
 * Store persisting each field under its own key in a `KeyValueStorage` (sync or async).
 * `get` is null without an access token (a lone refresh token reads as logged out) and on any
 * storage error; `set` removes the access token first and writes it last, so a crash mid-write
 * reads as logged out, never a mixed session. Neither method throws. `expiresAt` is read as
 * epoch seconds or ISO-8601 and written as epoch seconds. While logged out, the non-token
 * fields (`csrf`, `deviceId`, `lastCompanyId`) still read back so `deviceId` survives a reload.
 * `storageKey` (the access-token key) is set only for Web Storage, for cross-tab naming. Known limit:
 * the raw token values are not JSON, so without `BroadcastChannel` the `storage`-event fallback cannot
 * parse them and sync does not happen; with `BroadcastChannel` cross-tab works. A storage read error
 * makes `get()` return null, so the device-id bootstrap may then write `{ deviceId }` and drop the
 * other keys (for example a locked keychain whose `getItem` rejects while `removeItem` works).
 */
export function keyValueTokenStore(storage: KeyValueStorage, keys: Partial<StorageKeys> = {}): TokenStore {
  const k: StorageKeys = { ...DEFAULT_KEYS, ...keys };
  const store: TokenStore = {
    get: async () => {
      try {
        const out: Tokens = {};
        const read = async (key: string): Promise<string | undefined> => (await storage.getItem(key)) || undefined;
        const access = await read(k.accessToken);
        if (access) {
          out.accessToken = access;
          const refresh = await read(k.refreshToken);
          if (refresh) out.refreshToken = refresh;
          const exp = parseExpiry((await storage.getItem(k.expiresAt)) ?? null);
          if (exp !== undefined) out.expiresAt = exp;
        }
        const csrf = await read(k.csrf);
        if (csrf) out.csrf = csrf;
        const deviceId = await read(k.deviceId);
        if (deviceId) out.deviceId = deviceId;
        const lastCompanyId = await read(k.lastCompanyId);
        if (lastCompanyId) out.lastCompanyId = lastCompanyId;
        return Object.keys(out).length ? out : null;
      } catch {
        return null;
      }
    },
    set: async (t) => {
      if (t === null) {
        for (const key of Object.values(k)) {
          try {
            await storage.removeItem(key);
          } catch {
            /* attempt every key */
          }
        }
        return;
      }
      try {
        await storage.removeItem(k.accessToken);
        const put = async (key: string, v: string | undefined): Promise<void> => {
          if (v === undefined || v === '') await storage.removeItem(key);
          else await storage.setItem(key, v);
        };
        await put(k.refreshToken, t.refreshToken);
        await put(k.expiresAt, t.expiresAt === undefined ? undefined : String(t.expiresAt));
        await put(k.csrf, t.csrf);
        await put(k.deviceId, t.deviceId);
        await put(k.lastCompanyId, t.lastCompanyId);
        if (t.accessToken) await storage.setItem(k.accessToken, t.accessToken);
      } catch {
        /* storage failed mid-write: the access token stays removed, so this reads as logged out */
      }
    },
  };
  if (isWebStorage(storage)) Object.defineProperty(store, 'storageKey', { value: k.accessToken, enumerable: false });
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
