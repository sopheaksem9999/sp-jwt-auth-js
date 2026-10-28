import { afterEach, describe, expect, it } from 'vitest';
import { createJwtAuth, userSession } from '../../src/core/create-jwt-auth';
import { ensureDeviceId, keyValueTokenStore, memoryStore, webStorageStore } from '../../src/core/stores';
import type { KeyValueStorage, TokenStore, Tokens } from '../../src/core/stores';

type FakeStorage = Record<'getItem' | 'setItem' | 'removeItem', (...a: string[]) => unknown>;

const original = Object.getOwnPropertyDescriptor(globalThis, 'localStorage');
const originalSession = Object.getOwnPropertyDescriptor(globalThis, 'sessionStorage');

function installStorage(impl: FakeStorage | null): void {
  Object.defineProperty(globalThis, 'localStorage', {
    configurable: true,
    get: () => impl as unknown,
  });
}

function mapStorage(): { fake: FakeStorage; data: Map<string, string> } {
  const data = new Map<string, string>();
  const fake: FakeStorage = {
    getItem: (k) => (data.has(k as string) ? (data.get(k as string) as string) : null),
    setItem: (k, v) => void data.set(k as string, v as string),
    removeItem: (k) => void data.delete(k as string),
  };
  return { fake, data };
}

afterEach(() => {
  if (original) Object.defineProperty(globalThis, 'localStorage', original);
  else delete (globalThis as Record<string, unknown>).localStorage;
  if (originalSession) Object.defineProperty(globalThis, 'sessionStorage', originalSession);
  else delete (globalThis as Record<string, unknown>).sessionStorage;
});

describe('memoryStore', () => {
  it('does not alias stored state', async () => {
    const s = memoryStore();
    const input: Tokens = { accessToken: 'a' };
    await s.set(input);
    input.accessToken = 'mutated';
    const out = await s.get();
    if (out) out.accessToken = 'mutated2';
    expect(await s.get()).toEqual({ accessToken: 'a' });
  });

  it('round-trips and clears', async () => {
    const s = memoryStore();
    expect(await s.get()).toBeNull();
    await s.set({ accessToken: 'a', expiresAt: 10 });
    expect(await s.get()).toEqual({ accessToken: 'a', expiresAt: 10 });
    await s.set(null);
    expect(await s.get()).toBeNull();
  });
});

describe('webStorageStore', () => {
  it('round-trips through storage and set(null) removes the key', async () => {
    const { fake, data } = mapStorage();
    installStorage(fake);
    const s = webStorageStore('localStorage', 'k');
    await s.set({ accessToken: 'a' });
    expect(data.get('k')).toBe(JSON.stringify({ accessToken: 'a' }));
    expect(await s.get()).toEqual({ accessToken: 'a' });
    await s.set(null);
    expect(data.has('k')).toBe(false);
    expect(await s.get()).toBeNull();
  });

  it('returns null for arrays in storage', async () => {
    const { fake, data } = mapStorage();
    installStorage(fake);
    data.set('k', '[1,2]');
    expect(await webStorageStore('localStorage', 'k').get()).toBeNull();
  });

  it('returns null for corrupt JSON and non-object values', async () => {
    const { fake, data } = mapStorage();
    installStorage(fake);
    const s = webStorageStore('localStorage', 'k');
    data.set('k', '{not json');
    expect(await s.get()).toBeNull();
    data.set('k', '42');
    expect(await s.get()).toBeNull();
  });

  it('never throws when getItem/setItem/removeItem throw', async () => {
    const boom = (): never => {
      throw new Error('blocked');
    };
    installStorage({ getItem: boom, setItem: boom, removeItem: boom });
    const s = webStorageStore('localStorage', 'k');
    expect(await s.get()).toBeNull();
    await expect(s.set({ accessToken: 'a' })).resolves.toBeUndefined();
    await expect(s.set(null)).resolves.toBeUndefined();
  });

  it('never throws when reading globalThis.localStorage throws', async () => {
    Object.defineProperty(globalThis, 'localStorage', {
      configurable: true,
      get: () => {
        throw new Error('SecurityError');
      },
    });
    const s = webStorageStore('localStorage', 'k');
    expect(await s.get()).toBeNull();
    await expect(s.set({ accessToken: 'a' })).resolves.toBeUndefined();
    await expect(s.set(null)).resolves.toBeUndefined();
  });

  it('is a no-op when storage is missing', async () => {
    installStorage(null);
    const s = webStorageStore('sessionStorage', 'k');
    Object.defineProperty(globalThis, 'sessionStorage', { configurable: true, get: () => undefined });
    try {
      expect(await s.get()).toBeNull();
      await expect(s.set({ accessToken: 'a' })).resolves.toBeUndefined();
    } finally {
      if (originalSession) Object.defineProperty(globalThis, 'sessionStorage', originalSession);
      else delete (globalThis as Record<string, unknown>).sessionStorage;
    }
  });
});

describe('ensureDeviceId', () => {
  it('generates, persists, preserves other fields and is stable across calls', async () => {
    const s = memoryStore();
    await s.set({ accessToken: 'a' });
    const id = await ensureDeviceId(s);
    expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    expect(await ensureDeviceId(s)).toBe(id);
    expect(await s.get()).toEqual({ accessToken: 'a', deviceId: id });
  });

  it('keeps the deviceId after logout (set(null) then re-storing only {deviceId})', async () => {
    const s = memoryStore();
    const id = await ensureDeviceId(s);
    const before = await s.get();
    await s.set(null);
    await s.set({ deviceId: before?.deviceId });
    expect(await ensureDeviceId(s)).toBe(id);
  });

  it('still returns a usable id when the store cannot persist', async () => {
    const broken: TokenStore = {
      get: () => Promise.reject(new Error('x')),
      set: () => Promise.reject(new Error('x')),
    };
    const id = await ensureDeviceId(broken);
    expect(id).toMatch(/^[0-9a-f-]{36}$/);
  });

  it('concurrent calls on an empty store return the same persisted id', async () => {
    const s = memoryStore();
    const [a, b] = await Promise.all([ensureDeviceId(s), ensureDeviceId(s)]);
    expect(a).toBe(b);
    expect((await s.get())?.deviceId).toBe(a);
  });

  it('does not clobber a token write landing between get and set', async () => {
    const inner = memoryStore();
    let gate: (() => void) | undefined;
    let first = true;
    const slow: TokenStore = {
      set: (t) => inner.set(t),
      get: async () => {
        const snap = await inner.get();
        if (first) {
          first = false;
          await new Promise<void>((r) => (gate = r));
        }
        return snap;
      },
    };
    const p = ensureDeviceId(slow);
    await Promise.resolve();
    await inner.set({ accessToken: 'tok' });
    gate?.();
    const id = await p;
    expect(await inner.get()).toEqual({ accessToken: 'tok', deviceId: id });
  });

  it('returns the same id on sequential calls when setItem throws', async () => {
    const { fake } = mapStorage();
    installStorage({
      ...fake,
      setItem: () => {
        throw new Error('blocked');
      },
    });
    const s = webStorageStore('localStorage', 'k');
    const a = await ensureDeviceId(s);
    expect(await ensureDeviceId(s)).toBe(a);
  });
});

// ---- keyValueTokenStore (J1) ----

function recordingStorage(failAt?: number, sync = false) {
  const data = new Map<string, string>();
  const calls: string[] = [];
  let n = 0;
  const gate = <T>(label: string, fn: () => T): T | Promise<T> => {
    calls.push(label);
    n += 1;
    if (failAt !== undefined && n >= failAt) {
      if (sync) throw new Error('boom');
      return Promise.reject(new Error('boom'));
    }
    return sync ? fn() : Promise.resolve(fn());
  };
  const storage: KeyValueStorage = {
    getItem: (k) => gate(`get:${k}`, () => data.get(k) ?? null),
    setItem: (k, v) => gate(`set:${k}`, () => void data.set(k, v)),
    removeItem: (k) => gate(`remove:${k}`, () => void data.delete(k)),
  };
  return { storage, data, calls };
}

const full: Tokens = {
  accessToken: 'a1',
  refreshToken: 'r1',
  expiresAt: 1_900_000_000,
  csrf: 'c1',
  deviceId: 'd1',
  lastCompanyId: 'co1',
};

describe('keyValueTokenStore', () => {
  it('uses the default key names and round-trips a full session', async () => {
    const { storage, data } = recordingStorage();
    const store = keyValueTokenStore(storage);
    await store.set(full);
    expect(Object.fromEntries(data)).toEqual({
      sp_access_token: 'a1',
      sp_refresh_token: 'r1',
      sp_access_token_expires_at: '1900000000',
      sp_csrf: 'c1',
      sp_device_id: 'd1',
      sp_last_company_id: 'co1',
    });
    expect(await store.get()).toEqual(full);
  });

  it('honours overridden key names and reads a pre-seeded session', async () => {
    const { storage, data } = recordingStorage();
    data.set('tok', 'A');
    data.set('ref', 'R');
    data.set('exp', '1900000000');
    const store = keyValueTokenStore(storage, { accessToken: 'tok', refreshToken: 'ref', expiresAt: 'exp' });
    expect(await store.get()).toEqual({ accessToken: 'A', refreshToken: 'R', expiresAt: 1_900_000_000 });
    await store.set({ accessToken: 'B' });
    expect(data.get('tok')).toBe('B');
    expect(data.has('sp_access_token')).toBe(false);
  });

  it('reads an ISO-8601 expiry as epoch seconds and a corrupt expiry as undefined', async () => {
    const { storage, data } = recordingStorage();
    const store = keyValueTokenStore(storage);
    data.set('sp_access_token', 'A');
    data.set('sp_access_token_expires_at', '2030-03-17T17:46:40Z');
    expect((await store.get())?.expiresAt).toBe(1_900_000_000);
    data.set('sp_access_token_expires_at', 'garbage');
    expect((await store.get())?.expiresAt).toBeUndefined();
    data.set('sp_access_token_expires_at', '  ');
    expect((await store.get())?.expiresAt).toBeUndefined();
  });

  it('writes in a crash-safe order: removes the access token first and writes it last', async () => {
    const { storage, calls } = recordingStorage();
    await keyValueTokenStore(storage).set(full);
    expect(calls[0]).toBe('remove:sp_access_token');
    expect(calls[calls.length - 1]).toBe('set:sp_access_token');
    expect(calls.filter((c) => c === 'set:sp_access_token')).toHaveLength(1);
  });

  it('removes absent optional fields on set', async () => {
    const { storage, data } = recordingStorage();
    const store = keyValueTokenStore(storage);
    await store.set(full);
    await store.set({ accessToken: 'a2' });
    expect(Object.fromEntries(data)).toEqual({ sp_access_token: 'a2' });
  });

  it('reads null for an empty access token, and for a lone refresh token', async () => {
    const { storage, data } = recordingStorage();
    const store = keyValueTokenStore(storage);
    expect(await store.get()).toBeNull();
    data.set('sp_access_token', '');
    data.set('sp_refresh_token', 'r');
    expect(await store.get()).toBeNull();
    data.delete('sp_access_token');
    expect(await store.get()).toBeNull();
  });

  it('keeps non-token fields readable while logged out (device id survives a reload)', async () => {
    const { storage } = recordingStorage();
    const store = keyValueTokenStore(storage);
    await store.set(full);
    await store.set(null);
    await store.set({ deviceId: 'd1' });
    expect(await store.get()).toEqual({ deviceId: 'd1' });
  });

  it.each([false, true])('get() resolves null when storage rejects/throws (sync=%s)', async (sync) => {
    const { storage } = recordingStorage(1, sync);
    await expect(keyValueTokenStore(storage).get()).resolves.toBeNull();
  });

  it.each([false, true])('a failure at any operation never throws and leaves null or a complete session (sync=%s)', async (sync) => {
    for (let n = 1; n <= 8; n++) {
      const seed = recordingStorage();
      const old: Tokens = { accessToken: 'old', refreshToken: 'oldr', expiresAt: 1_800_000_000, csrf: 'oc' };
      await keyValueTokenStore(seed.storage).set(old);
      // Same backing data, but failing from operation n onwards.
      let ops = 0;
      const failing: KeyValueStorage = {
        getItem: (k) => seed.storage.getItem(k),
        setItem: (k, v) => {
          if (++ops >= n) {
            if (sync) throw new Error('boom');
            return Promise.reject(new Error('boom'));
          }
          return seed.storage.setItem(k, v);
        },
        removeItem: (k) => {
          if (++ops >= n) {
            if (sync) throw new Error('boom');
            return Promise.reject(new Error('boom'));
          }
          return seed.storage.removeItem(k);
        },
      };
      const store = keyValueTokenStore(failing);
      await expect(store.set(full)).resolves.toBeUndefined();
      const read = await keyValueTokenStore(seed.storage).get();
      if (read?.accessToken) {
        // A complete session (the untouched old one, or the new one); never a mix.
        expect([old, full]).toContainEqual(read);
      } else {
        expect(read?.accessToken).toBeUndefined();
        expect(read?.refreshToken).toBeUndefined();
      }
    }
  });

  it('set(null) attempts every key and swallows errors', async () => {
    const { storage, data } = recordingStorage();
    const store = keyValueTokenStore(storage);
    await store.set(full);
    const removed: string[] = [];
    const flaky: KeyValueStorage = {
      getItem: storage.getItem,
      setItem: storage.setItem,
      removeItem: (k) => {
        removed.push(k);
        if (k === 'sp_access_token') return Promise.reject(new Error('boom'));
        data.delete(k);
        return Promise.resolve();
      },
    };
    await expect(keyValueTokenStore(flaky).set(null)).resolves.toBeUndefined();
    expect(removed.sort()).toEqual(
      ['sp_access_token', 'sp_access_token_expires_at', 'sp_csrf', 'sp_device_id', 'sp_last_company_id', 'sp_refresh_token'].sort(),
    );
    expect([...data.keys()]).toEqual(['sp_access_token']);
  });

  it('sets storageKey only for Web Storage', () => {
    const { fake } = mapStorage();
    installStorage(fake);
    const web = keyValueTokenStore(fake as unknown as KeyValueStorage);
    expect(web.storageKey).toBe('sp_access_token');
    expect(Object.keys(web)).not.toContain('storageKey');
    expect(keyValueTokenStore(recordingStorage().storage).storageKey).toBeUndefined();
    installStorage(null);
    expect(keyValueTokenStore(fake as unknown as KeyValueStorage).storageKey).toBeUndefined();
  });

  it('works end to end with userSession: login, hydrate, refresh, logout keeps deviceId', async () => {
    const b64 = (x: string) => btoa(x).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const now = Math.floor(Date.now() / 1000);
    const jwt = (jti: string) => `${b64('{"alg":"none"}')}.${b64(JSON.stringify({ sub: '1', exp: now + 900, jti }))}.s`;
    const res = (body: unknown) => new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } });
    const fetchFn = (async (input: RequestInfo | URL) => {
      const u = String(input);
      if (u.endsWith('/login')) return res({ access_token: jwt('l'), refresh_token: 'r1', token_type: 'Bearer', expires_in: 900 });
      if (u.endsWith('/refresh')) return res({ access_token: jwt('n'), refresh_token: 'r2', token_type: 'Bearer', expires_in: 900 });
      return res({});
    }) as typeof fetch;
    const { storage, data } = recordingStorage();
    const make = () =>
      createJwtAuth({
        baseUrl: 'https://api.example.com',
        endpoints: { login: '/login', refresh: '/refresh' },
        mode: userSession({ storage: keyValueTokenStore(storage) }),
        fetch: fetchFn,
      });
    const a = make();
    await ensureDeviceId(keyValueTokenStore(storage));
    await a.login({ email: 'a@example.com', password: 'p' });
    expect(data.get('sp_refresh_token')).toBe('r1');
    const deviceId = data.get('sp_device_id');
    expect(deviceId).toBeTruthy();

    const b = make();
    await b.ready();
    expect(b.getState().status).toBe('authenticated');
    await b.refresh();
    expect(data.get('sp_refresh_token')).toBe('r2');
    expect(b.getState().claims?.jti).toBe('n');

    await b.logout();
    expect(data.has('sp_access_token')).toBe(false);
    expect(data.has('sp_refresh_token')).toBe(false);
    expect(data.get('sp_device_id')).toBe(deviceId);
    const c = make();
    await c.ready();
    expect(c.getState().status).toBe('anonymous');
  });
});
