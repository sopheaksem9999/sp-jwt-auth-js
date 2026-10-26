import { SpAuthError, isSpAuthError } from './errors';
import { createRefresher, waitFor } from './refresh';
import type { AuthMode, ModeContext, ModeRuntime } from './types';
import { bearerFrom } from './http';

/*
 * Server-side modes. None of them touches `window`, `document`, `localStorage`,
 * `BroadcastChannel` or `navigator`, and `crossTab` does not apply to them (no
 * channel, no lock): they hold no refresh token and persist nothing.
 */

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function utf8Base64(s: string): string {
  let bin = '';
  for (const b of new TextEncoder().encode(s)) bin += String.fromCharCode(b);
  return btoa(bin);
}

/** Options for `clientCredentials`. */
export interface ClientCredentialsOptions {
  /** Token URL (absolute, or a path joined to `baseUrl`); default `endpoints.oauthToken` (`/oauth/token`). */
  tokenUrl?: string;
  /** OAuth client id. */
  clientId: string;
  /** OAuth client secret. Kept in the closure only; never emitted, stored or put in an error. */
  clientSecret: string;
  /** Requested scope(s); an array is joined with spaces. */
  scope: string | readonly string[];
  /** Client authentication: `'basic'` (default, `Authorization: Basic …`) or `'body'` (`client_id`/`client_secret` form fields). */
  auth?: 'basic' | 'body';
  /** Lifetime in seconds assumed when the server sends no positive `expires_in`; default 3600. */
  defaultTtlSeconds?: number;
}

/**
 * OAuth 2.0 client-credentials mode, for a server acting as itself (spec §4.3).
 *
 * - POSTs `grant_type=client_credentials` and `scope` form-encoded to the token
 *   URL, authenticating the client by HTTP Basic or in the body. The token
 *   request has its own timeout and controller; a caller's `signal` only stops
 *   that caller's wait.
 * - The token lives in memory only: never in a store, an event, an error or the
 *   state (the state carries claims only when the token happens to be a JWT;
 *   OAuth tokens are opaque so they are `null`).
 * - Expiry is `now + expires_in` when that is positive, else `defaultTtlSeconds`
 *   (0.1.24 and earlier returned `expires_in: 0`).
 * - It re-fetches when fewer than `refreshAheadSeconds` remain (the lead time is
 *   clamped to half the token's lifetime, so a 30 s token with the default 60 is
 *   renewed after 15 s, not on every call), and on a 401
 *   via `handleUnauthorized` (resolves `true` after a successful fetch, or at
 *   once when the failed request used a token other than the current one).
 *   Concurrent callers share one request (single flight, per instance); a
 *   failure never sticks. A failed proactive renewal returns the still-valid token.
 * - A 400/401 from the token endpoint rejects with `SpAuthError` whose `code`
 *   is the RFC 6749 `error` (`invalid_client`, `invalid_scope`, …), drops the
 *   token and makes the state `anonymous`. Network errors, timeouts and 5xx
 *   reject with the state unchanged. `handleUnauthorized` rethrows these token-fetch
 *   failures (including `invalid_client`) rather than resolving `false`.
 * - Events: `token_fetched` (`expiresAt`) and `token_failed` (`status`, `code`).
 * - `logout()` is local only: it clears the in-memory token and makes no request.
 *   The token stays valid server-side until it expires (OAuth revocation needs a
 *   client-authenticated `/oauth/revoke`).
 *
 * Create one per process.
 */
export function clientCredentials(options: ClientCredentialsOptions): AuthMode {
  const { clientId, clientSecret } = options;
  const method = options.auth ?? 'basic';
  const scope = typeof options.scope === 'string' ? options.scope : options.scope.join(' ');
  return {
    kind: 'clientCredentials',
    create(ctx: ModeContext): ModeRuntime {
      let token: string | null = null;
      let expiresAt = 0;
      // When to renew: expiresAt minus the lead time, clamped to half the ttl so a short-lived token is not re-fetched on every call.
      let refreshAt = 0;
      // Bumped on logout so a fetch already in flight cannot resurrect the token.
      let generation = 0;

      const perform = async (): Promise<void> => {
        const started = generation;
        const form: Record<string, string> = { grant_type: 'client_credentials' };
        if (scope !== '') form.scope = scope;
        const headers: Record<string, string> = {};
        // Raw `id:secret` bytes, not form-encoded first: the server reads Symfony's
        // `Request::getUser()/getPassword()` with no urldecode (sp-jwt-auth
        // `src/Services/OAuthServerService.php:326-329`), so RFC 6749 §2.3.1 encoding would break `%`/`+` values.
        if (method === 'basic') headers.Authorization = `Basic ${utf8Base64(`${clientId}:${clientSecret}`)}`;
        else {
          form.client_id = clientId;
          form.client_secret = clientSecret;
        }
        let raw: unknown;
        try {
          ({ body: raw } = await ctx.http<unknown>({
            method: 'POST',
            endpoint: options.tokenUrl ?? ctx.endpoint('oauthToken', 'clientCredentials'),
            form,
            headers,
            module: 'clientCredentials',
          }));
        } catch (e) {
          const status = isSpAuthError(e) ? e.status : 0;
          ctx.emit({ type: 'token_failed', status, code: isSpAuthError(e) ? e.code : 'unknown' });
          if ((status === 400 || status === 401) && started === generation) {
            token = null;
            expiresAt = 0;
            refreshAt = 0;
            ctx.setAnonymous();
          }
          throw e;
        }
        const body = isRecord(raw) && typeof raw.access_token !== 'string' && isRecord(raw.data) ? raw.data : raw;
        const access = isRecord(body) ? body.access_token : undefined;
        if (typeof access !== 'string' || access === '') {
          // No `body` on purpose: an invalid response may still carry token values.
          const e = new SpAuthError({
            status: 0,
            code: 'unknown',
            message: 'Token response did not contain an access token',
            module: 'clientCredentials',
          });
          ctx.emit({ type: 'token_failed', status: 0, code: 'unknown' });
          throw e;
        }
        if (started !== generation) return;
        const expiresIn = isRecord(body) && typeof body.expires_in === 'number' ? body.expires_in : 0;
        const ttl = expiresIn > 0 ? expiresIn : (options.defaultTtlSeconds ?? 3600);
        token = access;
        expiresAt = ctx.now() + ttl;
        refreshAt = expiresAt - Math.min(ctx.options.refreshAheadSeconds ?? 60, ttl / 2);
        ctx.setAuthenticated(access);
        ctx.emit({ type: 'token_fetched', expiresAt });
      };
      const fetcher = createRefresher({ perform });

      const due = (): boolean => token === null || ctx.now() >= refreshAt;

      const getAccessToken = async (o?: { signal?: AbortSignal }): Promise<string | null> => {
        if (!due()) return token;
        try {
          await waitFor(fetcher.refresh(), o?.signal);
        } catch (e) {
          if (o?.signal?.aborted) throw e;
          // A transient failure while the current token is still valid is not the caller's problem yet.
          if (token !== null && expiresAt > ctx.now()) return token;
          throw e;
        }
        return token;
      };

      const clear = async (): Promise<void> => {
        generation++;
        token = null;
        expiresAt = 0;
        refreshAt = 0;
        ctx.setAnonymous();
      };

      return {
        getAccessToken,
        peekAccessToken: () => Promise.resolve(token),
        async getHeaders(): Promise<Record<string, string>> {
          const t = await getAccessToken();
          return t ? { Authorization: `Bearer ${t}` } : {};
        },
        async handleUnauthorized(o) {
          const failed = bearerFrom(o?.headers);
          if (failed !== null && token !== null && failed !== token) return true;
          if (o?.signal?.aborted) throw o.signal.reason;
          await waitFor(fetcher.refresh(), o?.signal);
          return true;
        },
        async hydrate() {
          if (ctx.getState().status === 'unknown') ctx.setAnonymous();
        },
        refresh: () => fetcher.refresh(),
        clearSession: clear,
        // The token is not revocable by a package route here: logout is local only, no request.
        logout: () => Promise.resolve(),
      };
    },
  };
}

/**
 * Static API-key mode: every request carries `Authorization: Bearer <key>`.
 * A 401 is final (`handleUnauthorized` resolves `false`). The key is never
 * stored or emitted, no request is made, the state is `authenticated` at once
 * with `claims: null`, and `logout()` is local only: it stops the instance sending
 * the key and changes nothing server-side.
 * One instance per process is correct. Throws `SpAuthError('not_configured')` for an empty key.
 */
export function apiKey(key: string): AuthMode {
  if (typeof key !== 'string' || key === '') {
    throw new SpAuthError({ status: 0, code: 'not_configured', message: 'apiKey requires a non-empty key', module: 'apiKey' });
  }
  return {
    kind: 'apiKey',
    create(ctx: ModeContext): ModeRuntime {
      let active = true;
      ctx.setAuthenticated(key);
      const get = (): Promise<string | null> => Promise.resolve(active ? key : null);
      return {
        getAccessToken: get,
        peekAccessToken: get,
        async getHeaders(): Promise<Record<string, string>> {
          return active ? { Authorization: `Bearer ${key}` } : {};
        },
        handleUnauthorized: () => Promise.resolve(false),
        async hydrate() {
          /* state is already set */
        },
        async clearSession() {
          active = false;
          ctx.setAnonymous();
        },
        logout: () => Promise.resolve(),
      };
    },
  };
}

/**
 * Mode for server code that already has a user's token (a Next.js server
 * component reading a cookie, Express or NestJS forwarding the caller's
 * `Authorization` header). `getToken` is called on EVERY `getHeaders` /
 * `getAccessToken`, never cached; an empty, `null` or `undefined` result means
 * anonymous (`{}` headers). A 401 is final (`handleUnauthorized` resolves
 * `false`): refreshing is the caller's job. The token is never stored or
 * emitted. `getState()` reflects the last token seen (claims decoded when it is
 * a JWT, best effort) and is `anonymous` until the first read. `logout()` is local
 * only and calls `getToken` once (to capture the token for the facade).
 *
 * IMPORTANT: server code holding a user's token must create the auth instance
 * PER REQUEST. A shared instance would run the next request as the previous user.
 */
export function staticToken(
  getToken: () => string | undefined | null | Promise<string | undefined | null>,
): AuthMode {
  return {
    kind: 'staticToken',
    create(ctx: ModeContext): ModeRuntime {
      const read = async (o?: { signal?: AbortSignal }): Promise<string | null> => {
        if (o?.signal?.aborted) throw o.signal.reason;
        const t = await getToken();
        if (typeof t === 'string' && t !== '') {
          ctx.setAuthenticated(t);
          return t;
        }
        ctx.setAnonymous();
        return null;
      };
      return {
        getAccessToken: read,
        peekAccessToken: () => read(),
        async getHeaders(): Promise<Record<string, string>> {
          const t = await read();
          return t ? { Authorization: `Bearer ${t}` } : {};
        },
        handleUnauthorized: () => Promise.resolve(false),
        async hydrate() {
          if (ctx.getState().status === 'unknown') ctx.setAnonymous();
        },
        async clearSession() {
          ctx.setAnonymous();
        },
        logout: () => Promise.resolve(),
      };
    },
  };
}
