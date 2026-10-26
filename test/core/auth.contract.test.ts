// Contract tests for the core session against the sp-jwt-test backend (see contract/README.md and contract/seed/README.md).
// Live when SP_CONTRACT_URL is set; otherwise replays test/fixtures/<backend-version>/. With neither a backend nor
// fixtures the whole suite is SKIPPED (never silently passing). Uses only the package's public API plus test/support.
//
// Matching in replay ignores secret VALUES (tokens are recorded as "[scrubbed]"), so two requests to the same URL with
// the same non-secret body are indistinguishable. Each scenario therefore refreshes through its own `?case=` query,
// which the backend ignores; that keeps e.g. a successful rotation and a reuse 401 from colliding on one fixture.
import { afterEach, describe, expect, it } from 'vitest';
import { createJwtAuth, memoryStore, presets, userSession } from '../../src';
import type { AuthEvent, JwtAuth, TokenStore } from '../../src';
import { liveOrReplay } from '../support/replay';

const { fetch: contractFetch, mode, baseUrl, hasFixtures } = liveOrReplay();
// TODO-verify: the seeded user and its login field names (see contract/seed/README.md).
const credentials = {
  email: process.env.SP_CONTRACT_USER_EMAIL ?? 'contract@example.test',
  password: process.env.SP_CONTRACT_USER_PASSWORD ?? 'replay-password',
};
// Any access token (TTL 15 min by default) is "near expiry" inside a 24 h window, so every getAccessToken() is due.
const ALWAYS_DUE_SECONDS = 24 * 60 * 60;

let refreshRequests = 0;
const countingFetch: typeof fetch = async (input, init) => {
  const url = new URL(input instanceof Request ? input.url : String(input));
  if (url.pathname.endsWith('/auth/refresh')) refreshRequests++;
  return contractFetch(input, init);
};

const created: JwtAuth[] = [];
let events: AuthEvent[] = [];

function client(storage: TokenStore, scenario: string): JwtAuth {
  const auth = createJwtAuth({
    baseUrl,
    ...presets.spJwtTest,
    endpoints: { ...presets.spJwtTest.endpoints, refresh: `${presets.spJwtTest.endpoints.refresh}?case=${scenario}` },
    mode: userSession({ storage }),
    refreshAheadSeconds: ALWAYS_DUE_SECONDS,
    fetch: countingFetch,
    onEvent: (e) => events.push(e),
  });
  created.push(auth);
  return auth;
}

afterEach(() => {
  for (const a of created.splice(0)) a.dispose?.();
  events = [];
  refreshRequests = 0;
});

describe.skipIf(mode !== 'live' && !hasFixtures)('auth contract (sp-jwt-test)', () => {
  // UNVERIFIED-CONTRACT: never run against a live backend yet; fixtures not recorded.
  it('login authenticates and stores a token pair', async () => {
    const store = memoryStore();
    const auth = client(store, 'login');
    expect(await auth.login(credentials)).toEqual({ status: 'authenticated' });
    expect(auth.getState().status).toBe('authenticated');
    const t = await store.get();
    expect(t?.accessToken).toBeTruthy();
    expect(t?.refreshToken).toBeTruthy();
    expect(events.some((e) => e.type === 'login')).toBe(true);
  });

  // UNVERIFIED-CONTRACT
  it('getAccessToken near expiry refreshes exactly once and rotates the pair', async () => {
    const store = memoryStore();
    const auth = client(store, 'refresh-once');
    await auth.login(credentials);
    const before = await store.get();
    const token = await auth.getAccessToken();
    expect(token).toBeTruthy();
    expect(refreshRequests).toBe(1);
    expect(auth.getState().status).toBe('authenticated');
    const after = await store.get();
    expect(after?.refreshToken).toBeTruthy();
    if (mode === 'live') {
      // Replayed fixtures hold "[scrubbed]" for every token, so the rotation itself is only checkable live.
      expect(after?.accessToken).not.toBe(before?.accessToken);
      expect(after?.refreshToken).not.toBe(before?.refreshToken);
      expect(token).toBe(after?.accessToken);
    }
    expect(events.some((e) => e.type === 'refresh')).toBe(true);
  });

  // UNVERIFIED-CONTRACT: the reuse-detection claim (two parallel refreshes with one token log the user out) is spec §4.2.
  it('two instances sharing a store never log out under concurrent calls at expiry', async () => {
    const store = memoryStore(); // same store object: the instances serialise on its in-process lock
    const a = client(store, 'concurrent');
    const b = client(store, 'concurrent');
    await a.login(credentials);
    await b.ready();
    const tokens = await Promise.all([a.getAccessToken(), b.getAccessToken(), a.getAccessToken(), b.getAccessToken()]);
    for (const t of tokens) expect(t).toBeTruthy();
    expect(events.filter((e) => e.type === 'session_ended')).toEqual([]);
    expect(events.filter((e) => e.type === 'refresh_failed')).toEqual([]);
    expect(a.getState().status).toBe('authenticated');
    expect(b.getState().status).toBe('authenticated');
    expect((await store.get())?.refreshToken).toBeTruthy();
    if (mode === 'live') {
      // The second instance adopts the first one's rotation: a single refresh request, one shared token.
      expect(refreshRequests).toBe(1);
      expect(new Set(tokens).size).toBe(1);
    } else {
      // Replay cannot tell rotated tokens apart ("[scrubbed]"), so the adoption check may refresh once per instance.
      expect(refreshRequests).toBeLessThanOrEqual(2);
    }
  });

  // UNVERIFIED-CONTRACT
  it('logout clears the session and getHeaders is {}', async () => {
    const store = memoryStore();
    const auth = client(store, 'logout');
    await auth.login(credentials);
    await auth.logout();
    expect(auth.getState().status).toBe('anonymous');
    expect(await auth.getHeaders()).toEqual({});
    expect((await store.get())?.accessToken).toBeUndefined();
    expect(refreshRequests).toBe(0);
  });

  // UNVERIFIED-CONTRACT: relies on the backend's default reuse_detection (revoke the session) or at least a 401 for a rotated token.
  it('a refresh with an already-rotated (revoked) token ends the session', async () => {
    const storeA = memoryStore();
    const a = client(storeA, 'rotate');
    await a.login(credentials);
    const stale = await storeA.get(); // refresh token R0
    await a.getAccessToken(); // rotates: R0 is now revoked
    expect(refreshRequests).toBe(1);

    // A second client presents R0. `expiresAt` in the past makes its access token due immediately.
    const storeB = memoryStore();
    await storeB.set({ ...stale, expiresAt: Math.floor(Date.now() / 1000) - 1 });
    const b = client(storeB, 'revoked');
    await b.ready();
    expect(b.getState().status).toBe('authenticated');
    expect(await b.getAccessToken()).toBeNull();
    expect(b.getState().status).toBe('anonymous');
    expect(events.some((e) => e.type === 'session_ended')).toBe(true);
    expect(await b.getHeaders()).toEqual({});
    expect((await storeB.get())?.refreshToken).toBeUndefined();
  });
});
