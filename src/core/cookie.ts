import { decodeClaims } from './claims';
import { resolveSessionCrossTab } from './crosstab';
import type { BroadcastToken, TabMessage } from './crosstab';
import { SpAuthError, isSpAuthError } from './errors';
import { PACKAGE_REVOKE_PATH, bearerFrom } from './http';
import { createRefresher, isSessionEnded, sessionEndedError, waitFor } from './refresh';
import type { TokenStore, Tokens } from './stores';
import type { AuthMode, ModeContext, ModeRuntime } from './types';
import { findTokenPair, unwrap } from './unwrap';
import type { TokenPairRaw } from './unwrap';
// Type-only: erased at build time, so there is no runtime import cycle with user-session.
import type { UserSessionOptions } from './user-session';

/*
 * Cookie transport (spec §4.3). This file and the other feature-detecting
 * helpers (`stores.ts`, `crosstab.ts`) are the only places that touch browser
 * globals; here that is `document` (cookie read, tab-context check) and the
 * `BroadcastChannel` / `addEventListener` presence check, always behind
 * typeof checks and try/catch.
 *
 * Origins (server configuration, not done by this package):
 * - Same host, or a same-site subdomain (`app.example.com` -> `api.example.com`):
 *   works with the default `SameSite=strict`. For subdomains set
 *   `SP_JWT_REFRESH_COOKIE_DOMAIN=.example.com`, otherwise `sp_csrf` is host-only
 *   on the API and `readCookie` cannot see it; alternatively leave the domain
 *   unset and rely on the `X-SP-CSRF` response header, which a cross-origin
 *   script can read only when CORS lists it in `exposed_headers`.
 * - Different site: `SP_JWT_REFRESH_COOKIE_SAME_SITE=none` (forces Secure), CORS
 *   `supports_credentials` with exact origins, and `X-SP-CSRF` in
 *   `exposed_headers` (the host's `config/cors.php`). Without the exposed header
 *   the browser hides it, the client has no CSRF value, and refresh answers 403,
 *   reported as `SpAuthError('csrf_failed')` with a hint naming `exposed_headers`.
 */

/** `true` when a `document` object exists (a browser page; never on a server or an edge runtime). */
export function hasDocument(): boolean {
  try {
    const d = (globalThis as { document?: unknown }).document;
    return typeof d === 'object' && d !== null;
  } catch {
    return false;
  }
}

/** `true` when tabs can talk: `BroadcastChannel`, or (for a web-storage key) the `storage` event. */
function hasTabTransport(watchesStorage: boolean): boolean {
  try {
    const g = globalThis as { BroadcastChannel?: unknown; addEventListener?: unknown };
    return typeof g.BroadcastChannel === 'function' || (watchesStorage && typeof g.addEventListener === 'function');
  } catch {
    return false;
  }
}

/**
 * Reads a JavaScript-readable cookie by exact name from `document.cookie` and
 * URL-decodes it (the raw value is returned when it is not valid URL encoding).
 * Returns `null` when there is no `document` (server, edge runtime), when the
 * cookie is absent, or when reading throws (sandboxed frames). Used for the
 * CSRF double-submit value (`sp_csrf`); an httpOnly cookie is never visible here.
 */
export function readCookie(name: string): string | null {
  try {
    const doc = (globalThis as { document?: { cookie?: unknown } }).document;
    if (typeof doc !== 'object' || doc === null) return null;
    const all = doc.cookie;
    if (typeof all !== 'string' || all === '') return null;
    for (const part of all.split(';')) {
      const i = part.indexOf('=');
      if (i < 0 || part.slice(0, i).trim() !== name) continue;
      const raw = part.slice(i + 1).trim();
      try {
        return decodeURIComponent(raw);
      } catch {
        return raw;
      }
    }
  } catch {
    return null;
  }
  return null;
}

async function safeGet(store: TokenStore): Promise<Tokens | null> {
  try {
    return await store.get();
  } catch {
    return null;
  }
}

/** Only the non-secret fields the cookie transport may persist, in a fixed key order. */
function nonSecret(t: Tokens | null): Tokens {
  const out: Tokens = {};
  if (t?.csrf) out.csrf = t.csrf;
  if (t?.deviceId) out.deviceId = t.deviceId;
  if (t?.lastCompanyId) out.lastCompanyId = t.lastCompanyId;
  return out;
}

function hasSecrets(t: Tokens | null): boolean {
  return t !== null && ('accessToken' in t || 'refreshToken' in t || 'expiresAt' in t);
}

/**
 * The cookie transport of `userSession` (`transport: 'cookie'`, spec §4.3).
 *
 * - **Tokens.** The refresh token is the backend's httpOnly cookie: the client
 *   never reads, stores or sends it itself; login, second factor, refresh,
 *   logout, whoami and company switch send `credentials: 'include'`. A body
 *   `refresh_token` (backend `both` mode) is dropped unread. The access token
 *   and its expiry live in memory only. `storage` keeps only `csrf`, `deviceId`
 *   and `lastCompanyId` (tokens a former body-transport session left there are
 *   scrubbed at hydration).
 * - **CSRF double-submit.** After every cookie-setting response the value is
 *   taken from its `X-SP-CSRF` header, else from `readCookie('sp_csrf')` (browser
 *   only), persisted in `storage` and broadcast to other tabs. It is echoed as
 *   the `X-SP-CSRF` request header on refresh, revoke and company switch.
 *   Names are the `csrf` option; `csrf: false` turns it off.
 * - **Page load.** State stays `unknown` until `restore()`, which calls refresh
 *   once (see `JwtAuth.restore`). With no CSRF value at all it is `anonymous`
 *   without a request; a 401 is "not logged in" (no error, no events).
 * - **Refresh.** No body. Single flight per instance, then the cross-tab lock.
 *   Inside the lock a token another tab already broadcast (or delivered while
 *   waiting) is used when still outside the refresh-ahead window, with no
 *   request. 401 while signed in: CSRF cleared (`deviceId` kept), `anonymous`,
 *   `session_ended`; unless another tab broadcast a newer token meanwhile, which
 *   is adopted with `reuse_suspected`. 403: `SpAuthError('csrf_failed')`, the
 *   session and state are kept. Network, timeout, 5xx: kept, rethrown.
 * - **Logout.** Local state first (CSRF cleared, `deviceId` kept), then
 *   `endpoints.logout` or `/auth/token/revoke` with the bearer (when one was
 *   held) AND the cookie plus `X-SP-CSRF`; a 401 means already logged out.
 * - **Tabs, and servers.** Tokens and CSRF values are broadcast, and broadcast
 *   ones consumed, only in a real tab context: a `document`, a working
 *   `BroadcastChannel`/`storage`-event path, a cross-tab key that is explicit
 *   or comes from a `webStorageStore` (or an injected instance), and a store
 *   write that actually persisted. On a server (no `document`) the cookie is
 *   never read, nothing is broadcast or received, `restore()` without a CSRF
 *   value is `anonymous` with no request, and a 401 leaves it `anonymous`
 *   without throwing. Server rendering of user data keeps the route-handler pattern (§4.7).
 */
export function cookieSession(options: UserSessionOptions, store: TokenStore): AuthMode {
  const csrfEnabled = options.csrf !== false;
  const csrfOpts = options.csrf === false ? {} : (options.csrf ?? {});
  const headerName = csrfOpts.header ?? 'X-SP-CSRF';
  const cookieName = csrfOpts.cookie ?? 'sp_csrf';

  return {
    kind: 'userSession',
    create(ctx: ModeContext): ModeRuntime {
      const { crossTab, owned, named, injected } = resolveSessionCrossTab(options.crossTab, store);

      let access: string | null = null;
      let expiresAt: number | undefined;
      // Bumped by every clear (local or another tab's logout): an in-flight refresh must not resurrect the session.
      let clears = 0;
      // Whether a token response carried the CSRF header in this instance (drives the exposed_headers hint).
      let seenHeader = false;
      // CSRF value captured by the last clear, for the revoke call that follows it.
      let csrfAtClear: string | null = null;

      const ahead = (): number => ctx.options.refreshAheadSeconds ?? 60;
      const freshEnough = (exp: number | undefined): boolean => exp === undefined || exp - ctx.now() >= ahead();

      /** A real browser tab that can talk to its siblings (see the SECURITY note on `cookieSession`). */
      const tabContext = (): boolean =>
        crossTab !== null && named && hasDocument() && (injected || hasTabTransport(store.storageKey !== undefined));

      /** CSRF value to send: the stored one, else (browser only) the readable cookie. */
      const currentCsrf = async (): Promise<string | null> => {
        if (!csrfEnabled) return null;
        const stored = (await safeGet(store))?.csrf;
        if (stored) return stored;
        return hasDocument() ? readCookie(cookieName) : null;
      };

      /** CSRF value from a cookie-setting response: its header first, then (browser only) the readable cookie. */
      const csrfFrom = (response: Response | undefined): string | null => {
        if (!csrfEnabled) return null;
        let v: string | null = null;
        try {
          v = response?.headers.get(headerName) ?? null;
        } catch {
          v = null;
        }
        if (v) {
          seenHeader = true;
          return v;
        }
        return hasDocument() ? readCookie(cookieName) : null;
      };

      /** Rewrites the store with non-secret fields only; `true` when the write demonstrably persisted. */
      const writeStore = async (mutate: (t: Tokens) => void): Promise<boolean> => {
        const next = nonSecret(await safeGet(store));
        mutate(next);
        const clean = nonSecret(next);
        try {
          await store.set(Object.keys(clean).length > 0 ? clean : null);
        } catch {
          return false;
        }
        return JSON.stringify(nonSecret(await safeGet(store))) === JSON.stringify(clean);
      };

      const setToken = (token: string, exp: number | undefined): void => {
        access = token;
        expiresAt = exp;
        ctx.setAuthenticated(token);
      };

      const expiryOf = (pair: TokenPairRaw): number | undefined => {
        // Spec §4.5: JWT exp first, falling back to expires_in (opaque tokens). 0 means absent for both.
        const exp = decodeClaims(pair.access_token)?.exp;
        if (typeof exp === 'number' && exp > 0) return exp;
        return pair.expires_in > 0 ? ctx.now() + pair.expires_in : undefined;
      };

      /** Takes the access token (never the body refresh token) and the CSRF value from a token response. */
      const applyPair = async (pair: TokenPairRaw, response: Response | undefined): Promise<void> => {
        const token = pair.access_token;
        const exp = expiryOf(pair);
        const csrf = csrfFrom(response);
        const persisted = await writeStore((t) => {
          if (csrf) t.csrf = csrf;
        });
        setToken(token, exp);
        if (persisted && tabContext()) {
          const m: TabMessage = { type: 'tokens', accessToken: token, expiresAt: exp ?? 0 };
          if (csrf) m.csrf = csrf;
          crossTab?.broadcast(m);
        }
      };

      /**
       * Drops the in-memory session and the CSRF value (keeping `deviceId`), sets
       * `anonymous`. `sentCsrf`: only clear the stored CSRF when it is still the
       * value a failed refresh sent (another tab may have rotated it meanwhile).
       */
      const clear = async (o: { broadcast: boolean; sentCsrf?: string | null }): Promise<void> => {
        clears++;
        access = null;
        expiresAt = undefined;
        const prev = await safeGet(store);
        const keepStore = o.sentCsrf !== undefined && o.sentCsrf !== null && prev?.csrf !== undefined && prev.csrf !== o.sentCsrf;
        if (!keepStore) {
          try {
            await store.set(null);
            if (prev?.deviceId) await store.set({ deviceId: prev.deviceId });
          } catch {
            /* stores must not throw; state still goes anonymous */
          }
        }
        ctx.setAnonymous();
        if (o.broadcast && tabContext()) crossTab?.broadcast({ type: 'logout' });
      };

      const adoptBroadcast = async (b: BroadcastToken): Promise<void> => {
        setToken(b.accessToken, b.expiresAt > 0 ? b.expiresAt : undefined);
        const csrf = b.csrf;
        if (csrf && (await safeGet(store))?.csrf !== csrf) {
          await writeStore((t) => {
            t.csrf = csrf;
          });
        }
      };

      const fail = (e: unknown): void => {
        ctx.emit({ type: 'refresh_failed', status: isSpAuthError(e) ? e.status : 0, code: isSpAuthError(e) ? e.code : 'unknown' });
      };

      const csrfFailed = (e: SpAuthError, hint: boolean): SpAuthError => {
        let message = `Refresh was rejected with HTTP 403: the ${headerName} header was missing or did not match the ${cookieName} cookie (CSRF double-submit).`;
        if (hint) {
          message +=
            ` No ${headerName} value was read from a token response. If the API is on another site, add '${headerName}'` +
            ' to the CORS exposed_headers (config/cors.php, with supports_credentials) so the browser lets the client read it;' +
            ' on a same-site subdomain set SP_JWT_REFRESH_COOKIE_DOMAIN or expose the header.';
        }
        return new SpAuthError({
          status: 403,
          code: 'csrf_failed',
          message,
          module: 'refresh',
          requestId: e.requestId,
          body: e.body,
          response: e.response,
          cause: e,
        });
      };

      /** One cookie refresh, run holding the in-process queue and the cross-tab lock. */
      const rotate = async (startedWith: string | null, clearsAtStart: number): Promise<void> => {
        // Another tab's token arrived while we waited (delivered, or only recorded): use it, no request.
        if (access !== null && access !== startedWith && freshEnough(expiresAt)) {
          ctx.emit({ type: 'refresh', adopted: true });
          return;
        }
        if (tabContext()) {
          const b = crossTab?.lastBroadcast();
          if (b && b.accessToken !== startedWith && b.expiresAt - ctx.now() >= ahead()) {
            await adoptBroadcast(b);
            ctx.emit({ type: 'refresh', adopted: true });
            return;
          }
        }

        // Read inside the lock: a tab that just rotated has already stored the new value.
        const csrf = await currentCsrf();
        if (csrfEnabled && !csrf && startedWith === null) throw sessionEndedError(0); // nothing to refresh with

        const headers: Record<string, string> = {};
        if (csrf) headers[headerName] = csrf;
        let raw: unknown;
        let response: Response;
        try {
          // No body: the cookie is the refresh token (in cookie mode the backend ignores a body one).
          ({ body: raw, response } = await ctx.http<unknown>({
            method: 'POST',
            endpoint: ctx.endpoint('refresh', 'refresh'),
            headers,
            device: true,
            credentials: 'include',
            module: 'refresh',
          }));
        } catch (e) {
          if (isSpAuthError(e) && e.status === 401) {
            if (clears !== clearsAtStart) throw sessionEndedError(401, e); // logged out meanwhile: nothing to clear
            if (tabContext()) {
              // Another tab rotated while our request was in flight (no shared lock): continue with its token.
              if (access !== null && access !== startedWith && expiresAt !== undefined && expiresAt > ctx.now()) {
                ctx.emit({ type: 'reuse_suspected', status: 401 });
                return;
              }
              const b = crossTab?.lastBroadcast();
              if (b && b.accessToken !== startedWith && b.expiresAt > ctx.now()) {
                await adoptBroadcast(b);
                ctx.emit({ type: 'reuse_suspected', status: 401 });
                return;
              }
            }
            if (startedWith === null) {
              // Page-load restore (or a refresh with no session): "not logged in", quietly.
              await clear({ broadcast: false, sentCsrf: csrf });
              throw sessionEndedError(401, e);
            }
            fail(e);
            await clear({ broadcast: true, sentCsrf: csrf });
            ctx.emit({ type: 'session_ended' });
            throw sessionEndedError(401, e);
          }
          if (isSpAuthError(e) && e.status === 403) {
            const err = csrfFailed(e, !csrf || !seenHeader);
            fail(err);
            throw err;
          }
          fail(e);
          throw e;
        }

        const pair = findTokenPair(unwrap(ctx.options.unwrap ?? 'raw', raw));
        if (!pair) {
          // No `body` on purpose: an invalid response may still carry token values.
          const e = new SpAuthError({ status: 0, code: 'unknown', message: 'Refresh response did not contain a token pair', module: 'refresh' });
          fail(e);
          throw e;
        }
        if (clears !== clearsAtStart) throw sessionEndedError(0); // logged out meanwhile: do not resurrect
        await applyPair(pair, response);
        ctx.emit({ type: 'refresh' });
      };

      // Refreshes and company switches take turns through this in-process queue, then the cross-tab lock.
      let queue: Promise<unknown> = Promise.resolve();
      const exclusive = <T>(fn: () => Promise<T>): Promise<T> => {
        const run = queue.then(fn, fn);
        queue = run.catch(() => undefined);
        return run;
      };
      const locked = <T>(fn: () => Promise<T>): Promise<T> => exclusive(() => (crossTab ? crossTab.withLock(fn) : fn()));

      const refresher = createRefresher({
        perform: () =>
          exclusive(() => {
            const startedWith = access;
            const clearsAtStart = clears;
            const run = (): Promise<void> => rotate(startedWith, clearsAtStart);
            return crossTab ? crossTab.withLock(run) : run();
          }),
      });

      const onTabMessage = async (m: TabMessage): Promise<void> => {
        if (!tabContext()) return;
        if (m.type === 'logout') {
          clears++;
          access = null;
          expiresAt = undefined;
          ctx.setAnonymous();
          // The cookie is gone; the sender already cleared a shared store, a private one still holds the value.
          if ((await safeGet(store))?.csrf) {
            await writeStore((t) => {
              delete t.csrf;
            });
          }
          return;
        }
        if (m.accessToken === access) return;
        await adoptBroadcast(m);
      };

      let unsubscribe: (() => void) | null = null;
      let disposed = false;
      // Subscribed on first use and only in a real tab: a server never opens a channel for this.
      const listen = (): void => {
        if (disposed || unsubscribe || !crossTab || !tabContext()) return;
        unsubscribe = crossTab.onMessage((m) => {
          void onTabMessage(m);
        });
      };

      const refresh = (): Promise<void> => {
        listen();
        return refresher.refresh();
      };

      const getAccessToken = async (o?: { signal?: AbortSignal }): Promise<string | null> => {
        const held = access;
        if (held === null) return null;
        if (freshEnough(expiresAt)) return held;
        const expired = expiresAt !== undefined && expiresAt <= ctx.now();
        if (o?.signal?.aborted) throw o.signal.reason;
        try {
          await waitFor(refresh(), o?.signal);
        } catch (e) {
          if (o?.signal?.aborted && e === o.signal.reason) throw e;
          if (isSessionEnded(e)) return null;
          if (!expired) return held; // transient failure: the current token is still valid
          throw e;
        }
        return access;
      };

      return {
        store,
        credentials: 'include',
        getAccessToken,
        peekAccessToken: () => Promise.resolve(access),
        async getHeaders(): Promise<Record<string, string>> {
          const t = await getAccessToken();
          return t ? { Authorization: `Bearer ${t}` } : {};
        },
        async handleUnauthorized(o) {
          if (access === null) return false;
          // The failed request used an older token: a refresh already happened, so just retry (§4.5 rule 4).
          const failed = bearerFrom(o?.headers);
          if (failed !== null && failed !== access) return true;
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
          return locked(fn);
        },
        // The refresh token is the cookie: never in the body.
        switchCompanyBody: (companyId) => Promise.resolve({ company_id: companyId }),
        async tokenRequestHeaders(): Promise<Record<string, string>> {
          const csrf = await currentCsrf();
          return csrf ? { [headerName]: csrf } : {};
        },
        async hydrate() {
          listen();
          // Migration from the body transport: never keep tokens around in this mode.
          const t = await safeGet(store);
          if (hasSecrets(t)) {
            const clean = nonSecret(t);
            try {
              await store.set(Object.keys(clean).length > 0 ? clean : null);
            } catch {
              /* stores must not throw */
            }
          }
          // State stays `unknown` until restore(): the access token is only in memory.
        },
        async restore() {
          listen();
          if (access !== null) return;
          if (csrfEnabled && !(await currentCsrf())) {
            ctx.setAnonymous();
            return;
          }
          try {
            await refresh();
          } catch (e) {
            if (!isSessionEnded(e)) throw e; // csrf_failed, network, 5xx: state unchanged
            if (access === null) ctx.setAnonymous();
          }
        },
        async acceptTokens(rawBody, response) {
          const pair = findTokenPair(unwrap(ctx.options.unwrap ?? 'raw', rawBody));
          if (!pair) {
            // No `body`: in `both` mode it may hold a refresh token.
            throw new SpAuthError({ status: 0, code: 'unknown', message: 'Response did not contain a token pair', module: 'userSession' });
          }
          await applyPair(pair, response);
        },
        async clearSession() {
          csrfAtClear = await currentCsrf();
          await clear({ broadcast: true });
        },
        async logout({ everywhere, accessToken }) {
          const csrf = csrfAtClear;
          csrfAtClear = null;
          // No access token and no CSRF value: no session and no cookie to revoke (always the case on a server).
          if (!accessToken && !csrf && (csrfEnabled || !hasDocument())) return;
          const headers: Record<string, string> = {};
          if (accessToken) headers.Authorization = `Bearer ${accessToken}`;
          if (csrf) headers[headerName] = csrf;
          const host = ctx.options.endpoints.logout;
          await ctx.http({
            method: 'POST',
            endpoint: host || PACKAGE_REVOKE_PATH,
            body: host && everywhere ? { everywhere: true } : undefined,
            headers,
            credentials: 'include',
            module: 'logout',
          });
        },
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
