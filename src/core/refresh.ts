import { SpAuthError, isSpAuthError } from './errors';
import type { TokenStore, Tokens } from './stores';
import type { ModeContext } from './types';
import { findTokenPair, unwrap } from './unwrap';

/** Single-flight refresher: concurrent callers share one in-flight refresh. */
export interface Refresher {
  /**
   * Starts a refresh, or joins the one already running. The shared promise is
   * dropped once it settles, so a failure never sticks: the next call starts a
   * new refresh.
   */
  refresh(): Promise<void>;
}

/** What `createRefresher` runs; called at most once at a time. */
export interface RefresherDeps {
  /** Performs one refresh (request, store, state). */
  perform(): Promise<void>;
}

/**
 * Wraps `perform` in a single-flight gate (spec §4.5 rule 2). Every refresh
 * rotates the refresh token server-side, and presenting the old one again is
 * reuse, which ends the session; sharing one promise prevents that in-process.
 */
export function createRefresher(deps: RefresherDeps): Refresher {
  let inflight: Promise<void> | null = null;
  return {
    refresh(): Promise<void> {
      if (inflight) return inflight;
      // Started on a microtask so a synchronous throw still lands in `finally`.
      const p: Promise<void> = Promise.resolve()
        .then(() => deps.perform())
        .finally(() => {
          if (inflight === p) inflight = null;
        });
      inflight = p;
      return p;
    },
  };
}

/**
 * Waits for `p` on behalf of one caller. Aborting `signal` rejects only this
 * wait (with the signal's reason); `p` itself, and anyone else awaiting it, is
 * unaffected.
 */
export function waitFor<T>(p: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (!signal) return p;
  if (signal.aborted) return Promise.reject(signal.reason as unknown);
  return new Promise<T>((resolve, reject) => {
    const onAbort = (): void => reject(signal.reason as unknown);
    signal.addEventListener('abort', onAbort, { once: true });
    p.then(
      (v) => {
        signal.removeEventListener('abort', onAbort);
        resolve(v);
      },
      (e: unknown) => {
        signal.removeEventListener('abort', onAbort);
        reject(e);
      },
    );
  });
}

/** Error thrown by a refresh when the session is over (refresh 401, or nothing to refresh with). */
export function sessionEndedError(status: number, cause?: unknown): SpAuthError {
  return new SpAuthError({
    status,
    code: 'session_ended',
    message: 'The session has ended',
    module: 'refresh',
    cause,
  });
}

/** `true` for the error `sessionEndedError` builds. */
export function isSessionEnded(e: unknown): boolean {
  return isSpAuthError(e) && e.code === 'session_ended';
}

/** Collaborators of the refresh-token rotation used by `userSession` (body transport). */
export interface TokenRefreshDeps {
  ctx: ModeContext;
  store: TokenStore;
  /** Clears tokens (keeping `deviceId`) and sets state `anonymous`. */
  clearSession(): Promise<void>;
}

async function safeGet(store: TokenStore): Promise<Tokens | null> {
  try {
    return await store.get();
  } catch {
    return null;
  }
}

/**
 * One refresh-token rotation (spec §4.5 rules 4 and 5): POSTs
 * `{ refresh_token }` to `endpoints.refresh` with device headers and no bearer,
 * stores the new pair (keeping `deviceId`/`csrf`/`lastCompanyId`), updates
 * state and emits `refresh`.
 *
 * - Refresh 401, or no refresh token stored: clears the session, emits
 *   `session_ended` and throws `SpAuthError('session_ended')`.
 * - Network error, timeout, 5xx or another 4xx: tokens and state are kept and
 *   the `SpAuthError` is rethrown.
 * - A 2xx without a valid pair: tokens kept, throws `SpAuthError('unknown')`.
 *
 * Every failure emits `refresh_failed` (`status`, `code` only). The request
 * uses the HTTP helper's own controller and timeout, never a caller's signal.
 * If the stored refresh token changed while the request was in flight (logout,
 * login), the response is not stored.
 */
export function performTokenRefresh(deps: TokenRefreshDeps): () => Promise<void> {
  const { ctx, store } = deps;

  const endSession = async (status: number, cause?: unknown): Promise<never> => {
    await deps.clearSession();
    ctx.emit({ type: 'session_ended' });
    throw sessionEndedError(status, cause);
  };

  const fail = (e: unknown): void => {
    const status = isSpAuthError(e) ? e.status : 0;
    const code = isSpAuthError(e) ? e.code : 'unknown';
    ctx.emit({ type: 'refresh_failed', status, code });
  };

  return async (): Promise<void> => {
    const current = await safeGet(store);
    const sent = current?.refreshToken;
    if (!sent) {
      if (current?.accessToken) await endSession(0);
      throw sessionEndedError(0);
    }

    let raw: unknown;
    try {
      const path = ctx.endpoint('refresh', 'refresh');
      ({ body: raw } = await ctx.http<unknown>({
        method: 'POST',
        endpoint: path,
        body: { refresh_token: sent },
        device: true,
        module: 'refresh',
      }));
    } catch (e) {
      fail(e);
      if (isSpAuthError(e) && e.status === 401) {
        if ((await safeGet(store))?.refreshToken === sent) await endSession(401, e);
        throw sessionEndedError(401, e);
      }
      throw e;
    }

    const pair = findTokenPair(unwrap(ctx.options.unwrap ?? 'raw', raw));
    if (!pair) {
      // No `body` on purpose: an invalid response may still carry token values.
      const e = new SpAuthError({
        status: 0,
        code: 'unknown',
        message: 'Refresh response did not contain a token pair',
        module: 'refresh',
      });
      fail(e);
      throw e;
    }

    const latest = await safeGet(store);
    if (latest?.refreshToken !== sent) {
      // Logged out (or logged in again) meanwhile: do not resurrect the old session.
      if (!latest?.refreshToken) throw sessionEndedError(0);
      return;
    }
    await store.set(ctx.tokensFromPair(pair, latest));
    ctx.setAuthenticated(pair.access_token);
    ctx.emit({ type: 'refresh' });
  };
}
