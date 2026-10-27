import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import readme from '../../README.md?raw';
import errorsSource from '../../src/core/errors.ts?raw';
import self from './readme-snippets.test.ts?raw';
import { createJwtAuth, memoryStore, presets, staticToken, userSession, webStorageStore } from '../../src/index';
import type { AuthState, JwtAuth } from '../../src/index';

// The README snippets below are copied verbatim (imports aside) between the region markers.
// The sync test at the bottom fails when README.md and this file drift apart.

interface Call {
  method: string;
  url: URL;
  headers: Headers;
  body: unknown;
}

const calls: Call[] = [];

const login = {
  user: { id: 1, email: 'ada@example.com' },
  token: { access_token: 'at-1', refresh_token: 'rt-1', expires_in: 900, token_type: 'Bearer' },
};

const fakeFetch = (async (input: string | URL, init?: RequestInit): Promise<Response> => {
  const url = new URL(String(input));
  const raw = init?.body;
  calls.push({ method: init?.method ?? 'GET', url, headers: new Headers(init?.headers), body: typeof raw === 'string' ? JSON.parse(raw) : raw });
  if (url.pathname === '/auth/login') {
    return new Response(JSON.stringify(login), { status: 200, headers: { 'Content-Type': 'application/json' } });
  }
  return new Response(null, { status: 204 }); // logout
}) as unknown as typeof fetch;

/** Minimal in-memory `localStorage` (Node and the edge runtime have none). */
function fakeLocalStorage(): Storage {
  const m = new Map<string, string>();
  return {
    getItem: (k: string) => m.get(k) ?? null,
    setItem: (k: string, v: string) => void m.set(k, v),
    removeItem: (k: string) => void m.delete(k),
  } as unknown as Storage;
}

beforeEach(() => {
  calls.length = 0;
  vi.stubGlobal('fetch', fakeFetch);
  vi.stubGlobal('localStorage', fakeLocalStorage());
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

async function quickStart(): Promise<void> {
  // #region snippet:quickstart
  // import { createJwtAuth, presets, userSession, webStorageStore } from '@sokpheak/sp-jwt-auth';

  const auth = createJwtAuth({
    baseUrl: 'https://api.example.com', // origin + the host's prefix (e.g. '/api/v2')
    ...presets.spJwtTest, // the host's endpoints and response shape; see "Presets"
    mode: userSession({ storage: webStorageStore('localStorage', 'app_auth') }),
  });

  const result = await auth.login({ email: 'ada@example.com', password: 'correct horse' });
  if (result.status === 'second_factor_required') {
    // hosts with a second factor also set endpoints.secondFactor
    await auth.verifySecondFactor(result.challenge, '123456');
  }

  console.log(auth.getState().status); // 'authenticated'
  console.log(await auth.getHeaders()); // { Authorization: 'Bearer ...' }, refreshed first when due

  await auth.logout();
  console.log(await auth.getHeaders()); // {}

  auth.dispose?.(); // when the client is discarded (an app unmount, a test)
  // #endregion
}

describe('README quick start', () => {
  it('runs against a fake fetch, logs in, builds headers and logs out', async () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    await quickStart();

    expect(calls[0]!.method).toBe('POST');
    expect(calls[0]!.url.href).toBe('https://api.example.com/auth/login');
    expect(calls[0]!.body).toEqual({ email: 'ada@example.com', password: 'correct horse' });
    expect(log).toHaveBeenNthCalledWith(1, 'authenticated');
    expect(log).toHaveBeenNthCalledWith(2, { Authorization: 'Bearer at-1' });
    expect(log).toHaveBeenNthCalledWith(3, {});
    // login, then logout (revoked server-side with the token captured before clearing); no refresh was due
    expect(calls.map((c) => c.url.pathname)).toEqual(['/auth/login', '/auth/logout']);
    expect(calls[1]!.headers.get('Authorization')).toBe('Bearer at-1');
  });
});

// Minimal stand-ins for each framework's primitive, so the snippets run without the frameworks.
function shallowRef<T>(v: T): { value: T } {
  return { value: v };
}
function useSyncExternalStore<T>(subscribe: (l: () => void) => () => void, get: () => T, getServer: () => T): T {
  const off = subscribe(() => undefined);
  off();
  expect(getServer()).toBe(get());
  return get();
}
function signal<T>(v: T): { (): T; set(n: T): void } {
  let current = v;
  const s = (): T => current;
  s.set = (n: T): void => {
    current = n;
  };
  return s;
}
function readable<T>(v: T, start: (set: (n: T) => void) => () => void): { get(): T; stop(): void } {
  let current = v;
  const stop = start((n) => {
    current = n;
  });
  return { get: () => current, stop };
}
function from(producer: (set: (n: AuthState) => void) => () => void): { get(): AuthState | undefined; stop(): void } {
  let current: AuthState | undefined;
  const stop = producer((n) => {
    current = n;
  });
  return { get: () => current, stop };
}

let auth: JwtAuth;

function vueGlue() {
  // #region snippet:vue
  // import { shallowRef } from 'vue';
  const state = shallowRef(auth.getState());
  auth.subscribe(() => (state.value = auth.getState()));
  // #endregion
  return state;
}

function reactGlue() {
  // #region snippet:react
  // import { useSyncExternalStore } from 'react';
  const state = useSyncExternalStore(auth.subscribe, auth.getState, auth.getState);
  // #endregion
  return state;
}

function angularGlue() {
  // #region snippet:angular
  // import { signal } from '@angular/core';
  const state = signal(auth.getState());
  auth.subscribe(() => state.set(auth.getState()));
  // provide it once: { provide: SP_AUTH, useValue: auth }
  // #endregion
  return state;
}

function svelteGlue() {
  // #region snippet:svelte
  // import { readable } from 'svelte/store';
  const authState = readable(auth.getState(), (set) => auth.subscribe(() => set(auth.getState())));
  // #endregion
  return authState;
}

function solidGlue() {
  // #region snippet:solid
  // import { from } from 'solid-js';
  const state = from((set) => auth.subscribe(() => set(auth.getState())));
  // #endregion
  return state;
}

describe('README framework glue', () => {
  beforeEach(() => {
    auth = createJwtAuth({ baseUrl: 'https://api.example.com', ...presets.spJwtTest, mode: userSession({ storage: memoryStore() }), fetch: fakeFetch });
  });
  afterEach(() => auth.dispose?.());

  it('every primitive follows the auth state after login and logout', async () => {
    const vue = vueGlue();
    const react = reactGlue();
    const angular = angularGlue();
    const svelte = svelteGlue();
    const solid = solidGlue();
    expect(react.status).toBe('unknown');

    await auth.login({ email: 'ada@example.com', password: 'x' });
    for (const s of [vue.value, angular(), svelte.get(), solid.get()]) expect(s?.status).toBe('authenticated');
    expect(vue.value).toBe(auth.getState()); // the snapshot is stable, so === is a valid change check
    expect(reactGlue().status).toBe('authenticated');

    await auth.logout();
    for (const s of [vue.value, angular(), svelte.get(), solid.get()]) expect(s?.status).toBe('anonymous');
    svelte.stop();
    solid.stop();
  });
});

describe('README servers: one instance per request', () => {
  it('seeds a private memoryStore, sends the token, and shares nothing between requests', async () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    // #region snippet:perrequest
    // import { createJwtAuth, memoryStore, presets, userSession } from '@sokpheak/sp-jwt-auth';

    async function authForRequest(accessToken: string | undefined) {
      const storage = memoryStore(); // never shared between requests or users
      if (accessToken) await storage.set({ accessToken });
      return createJwtAuth({
        baseUrl: 'https://api.example.com',
        ...presets.spJwtTest,
        mode: userSession({ storage, crossTab: false }), // no tabs on a server
      });
    }

    const requestAuth = await authForRequest('token-from-the-incoming-request');
    console.log(await requestAuth.getHeaders()); // { Authorization: 'Bearer token-from-the-incoming-request' }
    requestAuth.dispose?.();
    // #endregion
    expect(log).toHaveBeenCalledWith({ Authorization: 'Bearer token-from-the-incoming-request' });

    const other = await authForRequest(undefined); // another request: sees nothing of the first
    expect(await other.getHeaders()).toEqual({});
    other.dispose?.();
    expect(calls).toHaveLength(0);
  });
});

describe('README server modes: staticToken per request', () => {
  it('reads the token on every call and sends it to the host', async () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    // #region snippet:statictoken
    // import { createJwtAuth, presets, staticToken } from '@sokpheak/sp-jwt-auth';

    function authForIncomingRequest(req: { headers: Record<string, string | undefined> }) {
      return createJwtAuth({
        baseUrl: 'https://api.example.com',
        ...presets.spJwtTest,
        mode: staticToken(() => req.headers.authorization?.replace(/^Bearer /i, '')), // read on every call
      });
    }

    const userAuth = authForIncomingRequest({ headers: { authorization: 'Bearer user-token' } });
    console.log(await userAuth.getHeaders()); // { Authorization: 'Bearer user-token' }
    await userAuth.whoami(); // GET /me as that user
    // #endregion
    expect(log).toHaveBeenCalledWith({ Authorization: 'Bearer user-token' });
    expect(calls.map((c) => c.url.pathname)).toEqual(['/me']);
    expect(calls[0]!.headers.get('Authorization')).toBe('Bearer user-token');
    const anonymous = authForIncomingRequest({ headers: {} });
    expect(await anonymous.getHeaders()).toEqual({});
  });
});

describe('README cookie transport', () => {
  it('restores, logs in and out with credentials and X-SP-CSRF; localStorage never holds a token', async () => {
    const BODY_RT = 'rt-readme-cookie-never-stored';
    const cookieCalls: { path: string; headers: Headers; credentials: RequestCredentials | undefined; body: unknown }[] = [];
    vi.stubGlobal('fetch', (async (input: string | URL, init?: RequestInit): Promise<Response> => {
      const path = new URL(String(input)).pathname;
      cookieCalls.push({ path, headers: new Headers(init?.headers), credentials: init?.credentials, body: init?.body });
      if (path === '/auth/login') {
        // backend `both` mode: the body still carries refresh_token; the client drops it
        const body = { access_token: 'at-cookie', refresh_token: BODY_RT, expires_in: 900, token_type: 'Bearer' };
        return new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json', 'X-SP-CSRF': 'csrf-1' } });
      }
      return new Response(null, { status: 204 }); // revoke
    }) as unknown as typeof fetch);
    const written: string[] = [];
    const ls = fakeLocalStorage();
    const setItem = ls.setItem.bind(ls);
    ls.setItem = (k: string, v: string) => {
      written.push(v);
      setItem(k, v);
    };
    vi.stubGlobal('localStorage', ls);
    const log = vi.spyOn(console, 'log').mockImplementation(() => undefined);

    // #region snippet:cookie
    // import { createJwtAuth, userSession, webStorageStore } from '@sokpheak/sp-jwt-auth';

    const auth = createJwtAuth({
      baseUrl: 'https://api.example.com',
      // refresh and revoke stay on the package routes, under the cookie's path (/auth/token)
      endpoints: { login: '/auth/login' },
      mode: userSession({
        transport: 'cookie',
        storage: webStorageStore('localStorage', 'app_auth'), // only csrf, deviceId, lastCompanyId
      }),
    });

    await auth.restore(); // page load: one refresh through the cookie; no session -> 'anonymous'
    console.log(auth.getState().status); // 'anonymous'

    await auth.login({ email: 'ada@example.com', password: 'correct horse' });
    console.log(auth.getState().status); // 'authenticated'
    console.log(await auth.getHeaders()); // { Authorization: 'Bearer ...' }, from memory

    await auth.logout(); // revokes with the bearer AND the cookie (+ X-SP-CSRF)
    auth.dispose?.();
    // #endregion

    expect(log).toHaveBeenNthCalledWith(1, 'anonymous');
    expect(log).toHaveBeenNthCalledWith(2, 'authenticated');
    expect(log).toHaveBeenNthCalledWith(3, { Authorization: 'Bearer at-cookie' });
    // no csrf value yet, so restore() made no request
    expect(cookieCalls.map((c) => c.path)).toEqual(['/auth/login', '/auth/token/revoke']);
    expect(cookieCalls.map((c) => c.credentials)).toEqual(['include', 'include']);
    expect(cookieCalls[1]!.headers.get('Authorization')).toBe('Bearer at-cookie');
    expect(cookieCalls[1]!.headers.get('X-SP-CSRF')).toBe('csrf-1');
    expect(written).toContain(JSON.stringify({ csrf: 'csrf-1' }));
    for (const v of written) {
      expect(v).not.toContain(BODY_RT);
      expect(v).not.toContain('at-cookie');
    }
    expect(ls.getItem('app_auth')).toBeNull(); // logout cleared the csrf value
  });
});

function region(source: string, name: string): string {
  const m = new RegExp(`// #region snippet:${name}\\n([\\s\\S]*?)\\n\\s*// #endregion`).exec(source);
  if (m === null) throw new Error(`no region ${name} in test file`);
  return normalise(m[1]!);
}

function block(source: string, name: string): string {
  const m = new RegExp(`<!-- snippet:${name} -->\\s*\`\`\`ts\\n([\\s\\S]*?)\\n\`\`\``).exec(source);
  if (m === null) throw new Error(`no snippet ${name} in README`);
  return normalise(m[1]!);
}

/** Drops single-line imports (the test imports from src/) and common indentation. */
function normalise(code: string): string {
  const lines = code.split('\n').filter((l) => !/^\s*(\/\/\s*)?import .*;\s*$/.test(l));
  const indents = lines.filter((l) => l.trim() !== '').map((l) => /^ */.exec(l)![0].length);
  const cut = Math.min(...indents);
  return lines
    .map((l) => l.slice(cut).trimEnd())
    .join('\n')
    .trim();
}

describe('README stays in sync with this file', () => {
  it.each(['quickstart', 'vue', 'react', 'angular', 'svelte', 'solid', 'perrequest', 'cookie', 'statictoken'])('snippet %s matches', (name) => {
    expect(block(readme, name)).toBe(region(self, name));
  });

  it('the error code table lists exactly the SpAuthErrorCode members', () => {
    const union = /export type SpAuthErrorCode =([\s\S]*?);/.exec(errorsSource)![1]!;
    const declared = [...union.matchAll(/\|\s*'([a-z_0-9]+)'/g)].map((m) => m[1]!);
    const section = /## Error codes([\s\S]*?)\n## /.exec(readme)![1]!;
    const documented = [...section.matchAll(/^\| `([a-z_0-9]+)` \|/gm)].map((m) => m[1]!);
    expect(declared.length).toBeGreaterThan(5);
    expect(documented).toEqual(declared);
    // Raised by oauth (callback state / malformed callback), sessions and social (bad path values).
    expect(declared).toEqual(expect.arrayContaining(['invalid_state', 'invalid_request']));
    // A second factor is a LoginResult status, never a raised error.
    expect(declared).not.toContain('second_factor_required');
  });

  it('presets documented in the README exist', () => {
    for (const name of ['spJwtTest', 'speedxSaas']) expect(readme).toContain(`presets.${name}`);
    expect(Object.keys(presets).sort()).toEqual(['spJwtTest', 'speedxSaas'].sort());
  });
});
