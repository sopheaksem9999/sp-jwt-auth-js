import { SpAuthError, isSpAuthError } from './errors';
import type { CrossTab } from './crosstab';
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
 * unaffected. `p` always gets a rejection handler, so an abandoned shared
 * promise that later rejects is never an unhandled rejection.
 */
export function waitFor<T>(p: Promise<T>, signal?: AbortSignal): Promise<T> {
  p.catch(() => undefined);
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
  /** Cross-tab lock and broadcast (spec §4.5 rule 3); omitted = in-process single flight only. */
  crossTab?: CrossTab | null;
  /**
   * Cookie-transport seam (Task 20): the mode keeps no tokens in the store, so
   * inside the lock a token another tab broadcast is used instead of refreshing
   * while it is still outside the refresh-ahead window. Body transport leaves it unset.
   */
  useBroadcastedToken?: (b: { accessToken: string; expiresAt: number }) => void;
}

async function safeGet(store: TokenStore): Promise<Tokens | null> {
  try {
    return await store.get();
  } catch {
    return null;
  }
}

/**
 * One refresh-token rotation (spec §4.5 rules 3, 4 and 5). The refresh token
 * stored when the call starts is remembered; the rest runs inside
 * `crossTab.withLock` (when given):
 *
 * - First the store is re-read. If it now holds a different refresh token
 *   (another tab, or another instance, rotated meanwhile) those tokens are
 *   adopted: state updated, `refresh` emitted with `{ adopted: true }`, no request.
 * - Otherwise it POSTs `{ refresh_token }` to `endpoints.refresh` with device
 *   headers and no bearer, stores the new pair (keeping
 *   `deviceId`/`csrf`/`lastCompanyId`), updates state, emits `refresh` and
 *   broadcasts the new ACCESS token (never the refresh token) to other tabs.
 *
 * Failures:
 * - Refresh 401, or no refresh token stored: clears the session, emits
 *   `session_ended` and throws `SpAuthError('session_ended')`.
 * - Refresh 401 where the store meanwhile holds a different refresh token AND
 *   an access token (another tab rotated, or a re-login): that pair is adopted,
 *   only `reuse_suspected` is emitted (no `refresh_failed`), nothing is cleared
 *   and the refresh resolves. A different refresh token with no access token
 *   is treated as a plain refresh 401 (session ended).
 * - Network error, timeout, 5xx or another 4xx: tokens and state are kept and
 *   the `SpAuthError` is rethrown.
 * - A 2xx without a valid pair: tokens kept, throws `SpAuthError('unknown')`.
 *
 * Every other failure emits `refresh_failed` (`status`, `code` only). The
 * request uses the HTTP helper's own controller and timeout, never a caller's
 * signal. If the stored refresh token changed while the request was in flight
 * (logout, login, another tab), the response is not stored.
 */
export function performTokenRefresh(deps: TokenRefreshDeps): () => Promise<void> {
  const { ctx, store } = deps;
  const crossTab = deps.crossTab ?? null;

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

  /** Uses tokens another tab/instance already stored: state only, no request, no store write. */
  const adopt = (t: Tokens): void => {
    if (t.accessToken) ctx.setAuthenticated(t.accessToken);
  };

  const rotate = async (startedWith: string | undefined): Promise<void> => {
    if (deps.useBroadcastedToken && crossTab) {
      const b = crossTab.lastBroadcast();
      if (b && b.expiresAt - ctx.now() >= (ctx.options.refreshAheadSeconds ?? 60)) {
        deps.useBroadcastedToken(b);
        ctx.emit({ type: 'refresh', adopted: true });
        return;
      }
    }

    const current = await safeGet(store);
    const sent = current?.refreshToken;
    if (sent && sent !== startedWith && current.accessToken) {
      // Rotated by someone else while we waited for the lock: presenting `startedWith` now would be reuse.
      adopt(current);
      ctx.emit({ type: 'refresh', adopted: true });
      return;
    }
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
      if (isSpAuthError(e) && e.status === 401) {
        const latest = await safeGet(store);
        if (latest?.refreshToken && latest.refreshToken !== sent && latest.accessToken) {
          // Another tab rotated (or a re-login landed) while this request was in flight: the
          // server saw our token as reused, but a newer pair is stored, so continue with it.
          // NOTE: under the server's `revoke_session` reuse policy that pair may have been
          // revoked too; if so its next use gets a 401 and the session ends normally then.
          adopt(latest);
          ctx.emit({ type: 'reuse_suspected', status: 401 });
          return;
        }
        fail(e);
        // Logged out meanwhile: already anonymous, nothing to clear.
        if (!latest?.refreshToken) throw sessionEndedError(401, e);
        // Same token, or a newer refresh token with no access token to adopt: the session is over.
        await endSession(401, e);
      }
      fail(e);
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
      // Logged out (or logged in again, or rotated elsewhere) meanwhile: do not resurrect the old session.
      if (!latest?.refreshToken) throw sessionEndedError(0);
      adopt(latest);
      return;
    }
    const next = ctx.tokensFromPair(pair, latest);
    await store.set(next);
    ctx.setAuthenticated(pair.access_token);
    ctx.emit({ type: 'refresh' });
    crossTab?.broadcast({ type: 'tokens', accessToken: pair.access_token, expiresAt: next.expiresAt ?? 0 });
  };

  return async (): Promise<void> => {
    const startedWith = (await safeGet(store))?.refreshToken;
    if (!crossTab) return rotate(startedWith);
    return crossTab.withLock(() => rotate(startedWith));
  };
}
