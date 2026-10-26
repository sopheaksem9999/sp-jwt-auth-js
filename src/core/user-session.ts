import { SpAuthError } from './errors';
import { createRefresher, isSessionEnded, performTokenRefresh, waitFor } from './refresh';
import type { TokenStore, Tokens } from './stores';
import type { AuthMode, ModeContext, ModeRuntime } from './types';

/** Options for `userSession`. */
export interface UserSessionOptions {
  /** Where tokens are persisted. */
  storage: TokenStore;
  /** `'body'` (default): refresh token in storage. `'cookie'`: httpOnly cookie (not implemented yet). */
  transport?: 'body' | 'cookie';
}

async function safeGet(store: TokenStore): Promise<Tokens | null> {
  try {
    return await store.get();
  } catch {
    return null;
  }
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
 * through the same single flight.
 */
export function userSession(options: UserSessionOptions): AuthMode {
  if (options.transport === 'cookie') {
    throw new SpAuthError({
      status: 0,
      code: 'not_configured',
      message: 'cookie transport not implemented yet',
      module: 'userSession',
    });
  }
  const store = options.storage;
  return {
    kind: 'userSession',
    create(ctx: ModeContext): ModeRuntime {
      const clearSession = async (): Promise<void> => {
        const prev = await safeGet(store);
        try {
          await store.set(null);
          if (prev?.deviceId) await store.set({ deviceId: prev.deviceId });
        } catch {
          /* stores must not throw; state still goes anonymous */
        }
        ctx.setAnonymous();
      };

      const refresher = createRefresher({ perform: performTokenRefresh({ ctx, store, clearSession }) });
      const refresh = (): Promise<void> => refresher.refresh();
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
          try {
            await waitFor(refresh(), o?.signal);
            return true;
          } catch (e) {
            if (isSessionEnded(e)) return false;
            throw e;
          }
        },
        refresh,
        async hydrate() {
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
        },
        clearSession,
      };
    },
  };
}
