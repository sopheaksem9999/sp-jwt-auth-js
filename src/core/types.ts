import type { Claims } from './claims';
import type { HttpRequest, HttpResult } from './http';
import type { AuthState } from './state';
import type { TokenStore, Tokens } from './stores';
import type { TokenPairRaw, Unwrap } from './unwrap';

/**
 * Host and package routes (spec §4.4). Paths are joined to `baseUrl`; a full
 * `http(s)://` URL is used as is. Unset optional host routes make the module
 * that needs them throw `SpAuthError('not_configured')`.
 */
export interface Endpoints {
  /** Host password login, e.g. `/auth/login`. */
  login?: string;
  /** Host second-factor step, e.g. `/auth/login/2fa`. */
  secondFactor?: string;
  /** Refresh route; package default `/auth/token/refresh` (SaaS `/auth/refresh`). */
  refresh?: string;
  /** Host logout; when unset, logout POSTs the package `/auth/token/revoke`. */
  logout?: string;
  /** Host "who am I" route. */
  whoami?: string;
  /** Host company switch, e.g. SaaS `/auth/impersonate_in`. */
  switchCompany?: string;
  /** First-factor OTP prefix; package default `/otp`. */
  otp?: string;
  /** OAuth token route; package default `/oauth/token`. */
  oauthToken?: string;
  /** OAuth introspection; package default `/oauth/introspect`. */
  oauthIntrospect?: string;
  /** OAuth revocation; package default `/oauth/revoke`. */
  oauthRevoke?: string;
  /** JWKS; package default `/.well-known/sp-jwt-auth/jwks.json`. */
  jwks?: string;
  /** Resend a second-factor code (module `/mfa`). */
  secondFactorResend?: string;
  /** List sessions (module `/sessions`). */
  sessions?: string;
  /** Revoke one session; `:sid` placeholder. */
  sessionRevoke?: string;
  /** Revoke all other sessions. */
  sessionRevokeOthers?: string;
  /** Revoke a device; `:deviceId` placeholder. */
  deviceRevoke?: string;
  /** Social login redirect; `:provider` placeholder. */
  socialRedirect?: string;
  /** Social login callback; `:provider` placeholder. */
  socialCallback?: string;
  /** Forgot-password request (module `/account`). */
  forgotPassword?: string;
  /** Password reset (module `/account`). */
  resetPassword?: string;
  /** Resend e-mail verification (module `/account`). */
  resendVerification?: string;
  /** Verify e-mail (module `/account`). */
  verifyEmail?: string;
}

/** Second-factor challenge detected on a raw login response. */
export interface Challenge {
  kind: '2fa_token' | 'challenge_id';
  token: string;
}

/** Outcome of `login()`. */
export type LoginResult = { status: 'authenticated' } | { status: 'second_factor_required'; challenge: Challenge };

/**
 * Event passed to `onEvent`. Core emits `login`, `logout` (`everywhere`,
 * optional `remoteError: { status, code }` of a failed server-side revoke), `refresh` (`adopted: true` when another tab's
 * rotation was used instead of a request), `refresh_failed` (`status`, `code`),
 * `reuse_suspected` (`status`: a refresh 401 after another tab rotated; the
 * session continues) and `session_ended`; later tasks add their own types. Payloads never carry token
 * values. Hook errors are swallowed.
 */
export interface AuthEvent {
  type: string;
  [k: string]: unknown;
}

/**
 * Optional argument to `handleUnauthorized`: the failed request's `headers`
 * (its `Authorization: Bearer` token tells a stale-token 401 from one that
 * needs a refresh; lookup is case-insensitive) and a `signal` that stops this
 * caller's wait without cancelling the shared refresh.
 */
export interface UnauthorizedContext {
  headers?: Record<string, string>;
  signal?: AbortSignal;
}

/** Options for `createJwtAuth`. */
export interface JwtAuthOptions {
  /** Origin plus host prefix, e.g. `https://api.example.com/api/v2`. */
  baseUrl: string;
  /**
   * Host routes (§4.4); package routes are the defaults. Optional: omitted means
   * `{}` (refresh then uses the package `/auth/token/refresh`; a host-only route
   * such as `login` or `whoami` throws `not_configured` when used).
   */
  endpoints?: Endpoints;
  /** How host responses are unwrapped; default `'raw'`. */
  unwrap?: Unwrap;
  /** Exactly one auth mode, e.g. `userSession({ storage })`. */
  mode: AuthMode;
  /** `getAccessToken()` refreshes first when the token expires in fewer than this many seconds; default 60. */
  refreshAheadSeconds?: number;
  /** Claim that holds the company id; default `'company_id'`. */
  companyClaim?: string;
  /**
   * Opt-in device headers. When set, token-issuing calls (login, second factor,
   * refresh, and module calls made with `http({ device: true })`) send
   * `X-Device-Id` (`id`, else a generated id persisted in the mode's store) and
   * `X-Device-Name` (if `name`). Never sent to an origin other than `baseUrl`'s.
   */
  device?: { id?: string; name?: string };
  /** Builds the second-factor request body; defaults per `Challenge.kind`. */
  secondFactorBody?: (c: Challenge, code: string) => Record<string, unknown>;
  /** Fetch implementation; default `globalThis.fetch`. */
  fetch?: typeof fetch;
  /** Per-request timeout in ms; default 60000. */
  timeoutMs?: number;
  /** Event hook; exceptions are swallowed. */
  onEvent?: (e: AuthEvent) => void;
}

/** Shared services handed to a mode when `createJwtAuth` instantiates it. */
export interface ModeContext {
  /** The options passed to `createJwtAuth`, with `endpoints` always set (`{}` when omitted). */
  readonly options: Readonly<JwtAuthOptions & { endpoints: Endpoints }>;
  /** Request helper (same as `JwtAuth.http`). */
  http<T>(req: HttpRequest): Promise<HttpResult<T>>;
  /** Endpoint lookup (same as `JwtAuth.endpoint`). */
  endpoint(name: keyof Endpoints, module: string): string;
  /** Emits an event to `onEvent`, swallowing hook errors. */
  emit(e: AuthEvent): void;
  /** Unwraps a raw body per `options.unwrap` and finds the token pair; throws `SpAuthError` if none. */
  extractPair(rawBody: unknown, module?: string): TokenPairRaw;
  /**
   * Builds stored `Tokens` from a pair, carrying over non-secret fields
   * (`deviceId`, `csrf`, `lastCompanyId`) from `previous`. `expiresAt` is the
   * JWT `exp` when it is > 0, else now + `expires_in` when that is > 0, else unset.
   */
  tokensFromPair(pair: TokenPairRaw, previous: Tokens | null): Tokens;
  /** Current state snapshot. */
  getState(): AuthState;
  /** Sets state to `authenticated` for this access token (claims, companyId, impersonated derived). */
  setAuthenticated(accessToken: string): void;
  /** Sets state to `anonymous`. */
  setAnonymous(): void;
  /** Current time in epoch seconds. */
  now(): number;
}

/** What a mode instance provides to `createJwtAuth`. Optional members are capabilities; missing ones make the facade throw `not_configured`. */
export interface ModeRuntime {
  /** Store used for device id and tokens, if the mode persists anything. */
  readonly store?: TokenStore | null;
  /** `credentials` applied to login, second-factor, logout, whoami and company-switch calls (cookie transport). */
  readonly credentials?: 'include';
  /** Current access token (refreshed first when due), or `null`. Aborting `signal` stops this wait only. */
  getAccessToken(o?: { signal?: AbortSignal }): Promise<string | null>;
  /** Stored access token as is, without refreshing (used by logout); defaults to `getAccessToken`. */
  peekAccessToken?(): Promise<string | null>;
  /** Auth headers for API calls (`{}` when there is no token). */
  getHeaders(): Promise<Record<string, string>>;
  /**
   * Called on a 401: `true` when the request may be retried, `false` when the
   * session is gone; rejects on a transient refresh failure (tokens kept).
   * See `UnauthorizedContext` for the optional argument.
   */
  handleUnauthorized(failed?: UnauthorizedContext): Promise<boolean>;
  /** Reads persisted state once and resolves `unknown` to `authenticated`/`anonymous`. */
  hydrate?(): Promise<void>;
  /**
   * Unwraps a raw body, stores the pair and updates state. `response` is the
   * token response itself (cookie transport reads its `X-SP-CSRF` header).
   */
  acceptTokens?(rawBody: unknown, response?: Response): Promise<void>;
  /** Clears tokens (keeping `deviceId`) and sets state `anonymous`; no network. */
  clearSession?(): Promise<void>;
  /** Single-flight refresh; rejects `SpAuthError('session_ended')` when the session is over. */
  refresh?(): Promise<void>;
  /**
   * Server-side part of logout, replacing the default. The facade has already
   * cleared the session; `accessToken` is the token captured before clearing.
   */
  logout?(o: { everywhere?: boolean; accessToken: string | null }): Promise<void>;
  /**
   * Runs `fn` exclusively with respect to refreshes (in-process and cross-tab),
   * so a call that consumes the refresh token (company switch) cannot race one.
   * Without it the facade runs `fn` directly.
   */
  withRefreshLock?<T>(fn: () => Promise<T>): Promise<T>;
  /**
   * Request body for the company-switch call. Body transport: `{ company_id,
   * refresh_token }` with the stored refresh token (call it inside
   * `withRefreshLock`); the cookie transport omits the token. Without it the
   * facade sends `{ company_id }` only.
   */
  switchCompanyBody?(companyId: string | number): Promise<Record<string, unknown>>;
  /**
   * Extra headers for facade calls that rotate tokens through the refresh
   * cookie (company switch): the cookie transport's `X-SP-CSRF`. Without it, none.
   */
  tokenRequestHeaders?(): Promise<Record<string, string>>;
  /**
   * After a 403 on such a call: replacement headers for ONE retry (the cookie
   * transport's live `sp_csrf` value, when it differs from the one sent), or
   * `null` for no retry.
   */
  recoverCsrfHeaders?(sent: Record<string, string>): Promise<Record<string, string> | null>;
  /** Restores a session from the server on page load (cookie transport). Without it `JwtAuth.restore()` is `ready()`. */
  restore?(): Promise<void>;
  /** Releases listeners and channels (e.g. the cross-tab subscription). */
  dispose?(): void;
}

/** An auth strategy; `create` is called once by `createJwtAuth`. */
export interface AuthMode {
  kind: string;
  create(ctx: ModeContext): ModeRuntime;
}

/** The auth client returned by `createJwtAuth`. */
export interface JwtAuth {
  /** POSTs credentials to `endpoints.login`; stores the pair or returns the second-factor challenge. */
  login(credentials: Record<string, unknown>): Promise<LoginResult>;
  /** POSTs the challenge and code to `endpoints.secondFactor` and stores the pair. */
  verifySecondFactor(c: Challenge, code: string): Promise<void>;
  /**
   * Clears local state and storage first (keeping `deviceId`), then revokes
   * server-side (best effort) with the token captured before clearing. Never
   * rejects; a failure other than 401 is reported as `remoteError` (`{ status, code }`
   * only) on the `logout` event.
   */
  logout(o?: { everywhere?: boolean }): Promise<void>;
  /**
   * Current access token or `null`; refreshes first (single flight) when it is
   * within `refreshAheadSeconds` of expiry (or already past it). If that
   * proactive refresh fails transiently (network, timeout, 5xx, other non-401),
   * the still-valid current token is returned; the call rejects only once the
   * token has expired. A refresh 401 ends the session and resolves `null`.
   * Aborting `signal` rejects this call with the signal's reason without
   * cancelling the shared refresh.
   */
  getAccessToken(o?: { signal?: AbortSignal }): Promise<string | null>;
  /** `{ Authorization: 'Bearer …' }` or `{}`: the `ApiAuth` contract. */
  getHeaders(): Promise<Record<string, string>>;
  /**
   * 401 handler: refreshes once (shared single flight). Resolves `true` when the
   * request may be retried once, `false` when the session is gone (state
   * `anonymous`, `session_ended` emitted); rejects with the `SpAuthError` on a
   * network error, timeout, 5xx or other non-401 failure, tokens kept. When
   * `failed.headers` carries a bearer token that differs from the stored one, a
   * refresh already happened and it resolves `true` without a request.
   */
  handleUnauthorized(failed?: UnauthorizedContext): Promise<boolean>;
  /** Refreshes now (single flight); throws `not_configured` when the mode cannot refresh, `session_ended` when the session is over. */
  refresh(): Promise<void>;
  /**
   * Resolves once persisted state has been read. Body transport: the state has
   * left `unknown`. Cookie transport: the state stays `unknown` until `restore()`.
   */
  ready(): Promise<void>;
  /**
   * Page-load restore. Cookie transport: the access token lives in memory, so
   * this calls refresh once (the httpOnly cookie authenticates it):
   * - success: `authenticated`; already holding a token: no request;
   * - refresh 401 ("not logged in") or no CSRF value at all: `anonymous`, no
   *   error and no `session_ended` (no request in the no-CSRF case);
   * - 403: rejects `SpAuthError('csrf_failed')`, state unchanged (a setup error);
   * - network error, timeout, 5xx: rejects, state unchanged (call it again).
   * Other modes: same as `ready()`.
   */
  restore(): Promise<void>;
  /** Stable state snapshot. */
  getState(): AuthState;
  /** Registers a change listener; returns the unsubscribe function. */
  subscribe(l: () => void): () => void;
  /** Decodes `t`, or the current access token's claims when omitted. */
  decodeClaims(t?: string): Claims | null;
  /**
   * @internal Module surface: `'include'` when the mode's transport needs credentialed
   * requests (cookie transport), else `undefined`. Token-issuing modules pass it
   * as `HttpRequest.credentials`, like `login()` does.
   */
  readonly credentials?: 'include';
  /**
   * @internal Module surface: applies this instance's configured `unwrap`
   * option (including a function) to a raw response body.
   */
  unwrap(body: unknown): unknown;
  /** @internal Module surface: the `baseUrl` option, for modules that build absolute URLs (`social.redirectUrl`). */
  readonly baseUrl: string;
  /** Module surface: request helper. */
  http<T>(o: HttpRequest): Promise<HttpResult<T>>;
  /** Module surface: endpoint path; throws `SpAuthError('not_configured', module)` when unset. */
  endpoint(name: keyof Endpoints, module: string): string;
  /**
   * Module surface: unwrap → pair → store → state. Pass the token `response`
   * too, so the cookie transport can read its CSRF header.
   */
  acceptTokens(rawBody: unknown, response?: Response): Promise<void>;
  /** Module surface: clears the session without a network call. */
  clearSession(): Promise<void>;
  /**
   * GETs `endpoints.whoami` with the bearer token (one retry after a 401 via
   * `handleUnauthorized`), unwraps it per `unwrap`, caches it as `getState().user`
   * (only when the signed-in subject is still the one the request was sent for)
   * and returns it. Throws `not_configured` (module `core`) when `endpoints.whoami` is unset.
   */
  whoami(): Promise<unknown>;
  /**
   * POSTs `{ company_id, refresh_token }` to `endpoints.switchCompany` (SaaS
   * `impersonate_in`; the cookie transport sends `{ company_id }` with the
   * cookie and `X-SP-CSRF` instead) and stores the returned pair; `getState().companyId`
   * follows the new token and `lastCompanyId` is persisted. Runs under the
   * refresh lock, so it never races a refresh for the same refresh token. A
   * response without a valid pair throws `SpAuthError('unknown')` and keeps the
   * existing tokens. A logout (here or in another tab) while the request is in flight
   * wins: the response is dropped and the call rejects `SpAuthError('session_ended')`.
   * Throws `not_configured` when `endpoints.switchCompany` is unset.
   */
  switchCompany(companyId: string | number): Promise<void>;
  /** `true` when the access token's `scopes` claim holds `scope` or `*`. UI hint only: the server still decides. `false` when anonymous. */
  hasScope(scope: string): boolean;
  /** `true` when every scope is held (`*` holds all); `true` for `[]` while signed in, `false` when anonymous. UI hint only. */
  hasAllScopes(scopes: readonly string[]): boolean;
  /** `true` when at least one scope is held (`*` holds all); `false` for `[]` and when anonymous. UI hint only. */
  hasAnyScope(scopes: readonly string[]): boolean;
  /**
   * Releases what the mode holds open (the cross-tab subscription and channel).
   * Call it when the client is discarded (e.g. a test, or an app unmount); the
   * client should not be used afterwards. Idempotent.
   */
  dispose?(): void;
}
