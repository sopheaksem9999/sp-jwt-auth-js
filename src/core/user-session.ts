import { createCrossTab, storeScopedCrossTab } from './crosstab';
import type { CrossTab } from './crosstab';
import { SpAuthError } from './errors';
import { createRefresher, isSessionEnded, performTokenRefresh, waitFor } from './refresh';
import { memoryStore } from './stores';
import type { TokenStore, Tokens } from './stores';
import type { AuthMode, ModeContext, ModeRuntime } from './types';

/** Options for `userSession`. */
export interface UserSessionOptions {
  /**
   * Where tokens are persisted. Default: a fresh `memoryStore()` per `userSession()`
   * call (so on a server there are simply no tokens unless a store is passed, and
   * nothing touches `window` or `localStorage`).
   */
  storage?: TokenStore;
  /** `'body'` (default): refresh token in storage. `'cookie'`: httpOnly cookie (not implemented yet). */
  transport?: 'body' | 'cookie';
  /**
   * Cross-tab coordination (spec §4.5 rule 3).
   * - Default: ON for a `webStorageStore` (lock and channel named after its
   *   key). For a memory or custom store there is no cross-tab identity, so the
   *   default is a store-scoped in-process lock only (instances over the SAME
   *   store object serialise; no channel, no globals). That keeps per-request
   *   sessions on a server fully isolated.
   * - `true` or `{ key }`: ON with that key (`true` without a store key uses `'default'`).
   * - `{ instance }`: a ready-made `CrossTab` (tests, or to manage it yourself;
   *   `dispose()` then only unsubscribes and does not close it).
   * - `false`: no lock and no broadcast beyond the per-instance single flight.
   */
  crossTab?: boolean | { key?: string; instance?: CrossTab };
}

function resolveCrossTab(options: UserSessionOptions, store: TokenStore): { crossTab: CrossTab | null; owned: boolean } {
  const o = options.crossTab;
  if (o === false) return { crossTab: null, owned: false };
  if (typeof o === 'object' && o.instance) return { crossTab: o.instance, owned: false };
  const explicitKey = typeof o === 'object' ? o.key : undefined;
  if (o === true || explicitKey !== undefined || store.storageKey !== undefined) {
    const key = explicitKey ?? store.storageKey ?? 'default';
    // The storage-event fallback only makes sense for a web-storage key.
    return { crossTab: createCrossTab(key, { storageKey: store.storageKey ?? null }), owned: true };
  }
  return { crossTab: storeScopedCrossTab(store), owned: true };
}

async function safeGet(store: TokenStore): Promise<Tokens | null> {
  try {
    return await store.get();
  } catch {
    return null;
  }
}

/** Token from an `Authorization: Bearer …` header (header name and scheme case-insensitive), or `null`. */
export function bearerFrom(headers: Record<string, string> | undefined): string | null {
  if (!headers) return null;
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() !== 'authorization') continue;
    const m = /^\s*bearer\s+(\S+)\s*$/i.exec(v);
    return m?.[1] ?? null;
  }
  return null;
}

/**
 * Browser / single-user session mode: login, logout, tokens persisted in `storage`.
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
  if (options.transport === 'cookie') {
    throw new SpAuthError({
      status: 0,
      code: 'not_configured',
      message: 'cookie transport not implemented yet',
      module: 'userSession',
    });
  }
  const store = options.storage ?? memoryStore();
  return {
    kind: 'userSession',
    create(baseCtx: ModeContext): ModeRuntime {
      const { crossTab, owned } = resolveCrossTab(options, store);
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

      const clearSession = async (): Promise<void> => {
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
      const syncFromStore = async (): Promise<void> => {
        if (ctx.getState().status === 'unknown') return; // hydration will read the store
        const seen = generation;
        const t = await safeGet(store);
        if (seen !== generation) return;
        if (t?.accessToken) ctx.setAuthenticated(t.accessToken);
        else ctx.setAnonymous();
      };
      let unsubscribe: (() => void) | null = null;
      let disposed = false;
      // Subscribed on first use, so creating a session opens nothing.
      const listen = (): void => {
        if (disposed || unsubscribe || !crossTab) return;
        unsubscribe = crossTab.onMessage(() => {
          void syncFromStore();
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
      const rotate = performTokenRefresh({ ctx, store, clearSession, crossTab });
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
          ctx.emit({ type: 'session_ended' });
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
          const tokens = ctx.tokensFromPair(pair, await safeGet(store));
          await store.set(tokens);
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
