import { SpAuthError } from './errors';
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
 * stored (refresh is Task 15); with no refresh token the session is cleared
 * (`deviceId` kept) and hydrates as `anonymous`.
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

      const getAccessToken = async (): Promise<string | null> => (await safeGet(store))?.accessToken ?? null;

      return {
        store,
        getAccessToken,
        async getHeaders(): Promise<Record<string, string>> {
          const t = await getAccessToken();
          return t ? { Authorization: `Bearer ${t}` } : {};
        },
        async handleUnauthorized() {
          // Refresh-and-retry is Task 15; until then a 401 ends the session.
          await clearSession();
          ctx.emit({ type: 'session_ended' });
          return false;
        },
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
