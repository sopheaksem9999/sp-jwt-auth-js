import { cookieSession } from './cookie';
import type { CrossTab } from './crosstab';
import { resolveSessionCrossTab } from './crosstab';
import { bearerFrom } from './http';
import { createRefresher, isSessionEnded, performTokenRefresh, sessionEndedError, waitFor } from './refresh';
import { memoryStore } from './stores';
import type { TokenStore, Tokens } from './stores';
import type { AuthMode, ModeContext, ModeRuntime, SessionEndReason } from './types';

/** Options for `userSession`. */
export interface UserSessionOptions {
  /**
   * Where tokens are persisted. Default: a fresh `memoryStore()` per client (each
   * `createJwtAuth` given this mode gets its own), so on a server there are simply
   * no tokens unless a store is passed, nothing touches `window` or `localStorage`,
   * and a mode object reused for several clients never shares tokens between them.
   * A store passed here IS shared by every client created with this mode (by
   * design): never pass one store, or one mode holding it, to clients of different
   * users. With `transport: 'cookie'` it holds only non-secret state (`csrf`,
   * `deviceId`, `lastCompanyId`).
   */
  storage?: TokenStore;
  /**
   * `'body'` (default): the refresh token is kept in `storage` and sent in the
   * request body. `'cookie'` (spec §4.3, backend `SP_JWT_REFRESH_TRANSPORT=cookie`):
   * the refresh token is an httpOnly cookie JavaScript never sees, the access
   * token lives in memory only, and the app calls `auth.restore()` on page load.
   * Browser only; see `cookieSession` for the full behaviour.
   */
  transport?: 'body' | 'cookie';
  /**
   * Cookie transport only: the CSRF double-submit names, matching the backend's
   * `token_endpoints.csrf` config. Defaults `{ header: 'X-SP-CSRF', cookie: 'sp_csrf' }`.
   * `false` when the backend has CSRF switched off (`csrf.enabled = false`):
   * no header is sent and `restore()` always tries the refresh.
   */
  csrf?: { header?: string; cookie?: string } | false;
  /**
   * Cross-tab coordination (spec §4.5 rule 3).
   * - Default: ON for a `webStorageStore` (lock and channel named after its
   *   key). Cookie transport in a REAL browser tab (a `document`, Web Locks or
   *   `BroadcastChannel`, and not a Node-like runtime: `process.versions.node`
   *   unset): ON for any store, keyed by the cookie's scope
   *   (`cookie:<origin of baseUrl>`, `cookie:<location.origin>` for a relative
   *   `baseUrl`, else `cookie:default`), because every tab shares the one
   *   httpOnly refresh cookie and two tabs refreshing it at once would trip the
   *   server's reuse detection. A server or SSR process never gets that default,
   *   even with a global `document` (jsdom, happy-dom); pass `crossTab: false`
   *   there. Electron renderers (Node-like, but a real browser) pass `crossTab: true`.
   *   A browser with neither Web Locks nor `BroadcastChannel` falls back to the
   *   per-instance mutex, so tabs can still rotate the cookie at once (known limit).
   *   Otherwise (a memory or custom store with the body
   *   transport, or any server) there is no cross-tab identity, so the default is
   *   a store-scoped in-process lock only (instances over the SAME store object
   *   serialise; no channel, no globals). That keeps per-request sessions on a
   *   server fully isolated.
   * - `true` or `{ key }`: ON with that key (`true` without a store key uses `'default'`).
   * - `{ instance }`: a ready-made `CrossTab` (tests, or to manage it yourself;
   *   `dispose()` then only unsubscribes and does not close it).
   * - `false`: no lock and no broadcast beyond the per-instance single flight.
   */
  crossTab?: boolean | { key?: string; instance?: CrossTab };
  /**
   * Cookie transport only, in a browser tab with cross-tab coordination: when a
   * refresh had to WAIT for the cross-tab lock (another tab held it) and that
   * tab's new access token has not arrived yet, wait up to this many ms for its
   * broadcast before refreshing again. `BroadcastChannel` delivery and lock
   * grants are not ordered, so without it the waiting tab can rotate a second
   * time. Ends as soon as a message arrives; an uncontended refresh never waits;
   * the lock is held at most this much longer. Default `100`; `0` turns it off;
   * values above 2147483647 (the largest timer delay) are clamped to it.
   * Ignored by the body transport (its shared store is authoritative) and on servers.
   */
  broadcastGraceMs?: number;
}

async function safeGet(store: TokenStore): Promise<Tokens | null> {
  try {
    return await store.get();
  } catch {
    return null;
  }
}

/**
 * Browser / single-user session mode: login, logout, tokens persisted in `storage`
 * (body transport; `transport: 'cookie'` is described on `cookieSession`).
 *
 * Hydration: a stored access token hydrates as `authenticated`. If it is past
 * `expiresAt` it still hydrates as `authenticated` when a refresh token is
 * stored (the next `getAccessToken()` refreshes it); with no refresh token the
 * session is cleared (`deviceId` kept) and hydrates as `anonymous`.
 *
 * Refresh (spec §4.5): single-flight per instance. `getAccessToken()` refreshes
 * first when `expiresAt − now < refreshAheadSeconds` (default 60), including
 * when `expiresAt` is already past. If that proactive refresh fails transiently
 * (network, timeout, 5xx) the current token is still returned while it has not
 * expired; once expired, the error is rethrown. `handleUnauthorized()` refreshes
 * through the same single flight, unless the failed request's bearer token is
 * already older than the stored one (then it resolves `true` at once).
 *
 * Tabs (spec §4.5 rule 3, see `crossTab` for when it is on): each refresh runs
 * under the lock and first re-reads the store, adopting a pair another tab
 * already rotated. Login, refresh and every session clear are broadcast (access
 * token and expiry only); on a message, other instances re-read the shared
 * store and update their state, so it always follows the store. The channel is
 * opened on first use (hydration), never at creation; `JwtAuth.dispose()`
 * unsubscribes and closes it.
 */
export function userSession(options: UserSessionOptions = {}): AuthMode {
  if (options.transport === 'cookie') return cookieSession(options);
  return {
    kind: 'userSession',
    create(baseCtx: ModeContext): ModeRuntime {
      // Per client, not per userSession() call: a hoisted mode object must never share tokens between clients.
      const store = options.storage ?? memoryStore();
      const { crossTab, owned } = resolveSessionCrossTab(options.crossTab, store);
      // Bumped on every local state change, so a sync triggered by another tab never applies a stale read.
      let generation = 0;
      const ctx: ModeContext = {
        ...baseCtx,
        setAuthenticated(accessToken) {
          generation++;
          baseCtx.setAuthenticated(accessToken);
        },
        setAnonymous() {
          generation++;
          baseCtx.setAnonymous();
        },
      };

      // Bumped at the start of every clear: a token write in flight must not resurrect the session.
      let clears = 0;
      const clearSession = async (): Promise<void> => {
        clears++;
        const prev = await safeGet(store);
        try {
          await store.set(null);
          if (prev?.deviceId) await store.set({ deviceId: prev.deviceId });
        } catch {
          /* stores must not throw; state still goes anonymous */
        }
        ctx.setAnonymous();
        crossTab?.broadcast({ type: 'logout' });
      };

      // Body transport: the shared store is the source of truth, so a message only triggers a re-read.
      const syncFromStore = async (reason?: SessionEndReason): Promise<void> => {
        if (ctx.getState().status === 'unknown') return; // hydration will read the store
        const seen = generation;
        const t = await safeGet(store);
        if (seen !== generation) return;
        if (t?.accessToken) ctx.setAuthenticated(t.accessToken);
        else {
          const wasAuth = ctx.getState().status === 'authenticated';
          ctx.setAnonymous();
          if (wasAuth) {
            ctx.emit({ type: 'session_ended', reason: reason ?? 'storage_cleared' });
          }
        }
      };
      let unsubscribe: (() => void) | null = null;
      let disposed = false;
      // Subscribed on first use, so creating a session opens nothing.
      const listen = (): void => {
        if (disposed || unsubscribe || !crossTab) return;
        unsubscribe = crossTab.onMessage((m) => {
          void syncFromStore(m.type === 'logout' ? 'cross_tab_logout' : undefined);
        });
      };

      // Refreshes and refresh-token-consuming calls (company switch) take turns through this in-process queue,
      // then the cross-tab lock, always in that order.
      let queue: Promise<unknown> = Promise.resolve();
      const exclusive = <T>(fn: () => Promise<T>): Promise<T> => {
        const run = queue.then(fn, fn);
        queue = run.catch(() => undefined);
        return run;
      };
      const rotate = performTokenRefresh({ ctx, store, clearSession, crossTab, cleared: () => clears });
      const refresher = createRefresher({ perform: () => exclusive(rotate) });
      const refresh = (): Promise<void> => {
        listen();
        return refresher.refresh();
      };
      const aheadSeconds = (): number => ctx.options.refreshAheadSeconds ?? 60;

      const peekAccessToken = async (): Promise<string | null> => (await safeGet(store))?.accessToken ?? null;

      const getAccessToken = async (o?: { signal?: AbortSignal }): Promise<string | null> => {
        const t = await safeGet(store);
        const access = t?.accessToken;
        if (!access) return null;
        // Opaque tokens get expiresAt from expires_in at accept time; no expiry at all means never due.
        if (t.expiresAt === undefined || t.expiresAt - ctx.now() >= aheadSeconds()) return access;
        const expired = t.expiresAt <= ctx.now();
        if (!t.refreshToken) {
          if (!expired) return access;
          await clearSession();
          ctx.emit({ type: 'session_ended', reason: 'token_expired' });
          return null;
        }
        if (o?.signal?.aborted) throw o.signal.reason;
        try {
          await waitFor(refresh(), o?.signal);
        } catch (e) {
          if (o?.signal?.aborted && e === o.signal.reason) throw e;
          if (isSessionEnded(e)) return null;
          if (!expired) return access; // transient failure: the current token is still valid
          throw e;
        }
        return peekAccessToken();
      };

      return {
        store,
        getAccessToken,
        peekAccessToken,
        async getHeaders(): Promise<Record<string, string>> {
          const t = await getAccessToken();
          return t ? { Authorization: `Bearer ${t}` } : {};
        },
        async handleUnauthorized(o) {
          const t = await safeGet(store);
          if (!t?.accessToken && !t?.refreshToken) return false;
          // The failed request used an older token: a refresh already happened, so just retry (§4.5 rule 4).
          const failed = bearerFrom(o?.headers);
          if (failed !== null && t.accessToken && failed !== t.accessToken) return true;
          if (o?.signal?.aborted) throw o.signal.reason;
          try {
            await waitFor(refresh(), o?.signal);
            return true;
          } catch (e) {
            if (isSessionEnded(e)) return false;
            throw e;
          }
        },
        refresh,
        withRefreshLock<T>(fn: () => Promise<T>): Promise<T> {
          listen();
          return exclusive(() => (crossTab ? crossTab.withLock(fn) : fn()));
        },
        async switchCompanyBody(companyId) {
          const t = await safeGet(store);
          return { company_id: companyId, refresh_token: t?.refreshToken };
        },
        async hydrate() {
          listen();
          const t = await safeGet(store);
          if (ctx.getState().status !== 'unknown') return; // a login/logout already resolved state
          const access = t?.accessToken;
          if (!access) {
            ctx.setAnonymous();
            return;
          }
          const expired = t.expiresAt !== undefined && t.expiresAt > 0 && t.expiresAt <= ctx.now();
          if (expired && !t.refreshToken) {
            await clearSession();
            return;
          }
          ctx.setAuthenticated(access);
        },
        async acceptTokens(rawBody) {
          const pair = ctx.extractPair(rawBody);
          const clearsAtStart = clears;
          const tokens = ctx.tokensFromPair(pair, await safeGet(store));
          await store.set(tokens);
          if (clears !== clearsAtStart) {
            // Logged out during the write: undo ours if it landed after the clear, and report it.
            const after = await safeGet(store);
            if (after !== null && after.accessToken === tokens.accessToken) {
              const deviceId = after.deviceId;
              try {
                await store.set(null);
                if (deviceId) await store.set({ deviceId });
              } catch {
                /* stores must not throw */
              }
            }
            throw sessionEndedError(0);
          }
          ctx.setAuthenticated(pair.access_token);
          crossTab?.broadcast({ type: 'tokens', accessToken: pair.access_token, expiresAt: tokens.expiresAt ?? 0 });
        },
        clearSession,
        dispose() {
          disposed = true;
          unsubscribe?.();
          unsubscribe = null;
          if (owned) crossTab?.close();
        },
      };
    },
  };
}
