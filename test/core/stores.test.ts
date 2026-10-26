import { afterEach, describe, expect, it } from 'vitest';
import { ensureDeviceId, memoryStore, webStorageStore } from '../../src/core/stores';
import type { TokenStore, Tokens } from '../../src/core/stores';

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
