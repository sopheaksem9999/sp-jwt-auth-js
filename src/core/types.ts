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
 * Event passed to `onEvent`. This task emits `login`, `logout` and
 * `session_ended`; later tasks add their own types. Hook errors are swallowed.
 */
export interface AuthEvent {
  type: string;
  [k: string]: unknown;
}

/** Options for `createJwtAuth`. */
export interface JwtAuthOptions {
  /** Origin plus host prefix, e.g. `https://api.example.com/api/v2`. */
  baseUrl: string;
  /** Host routes (§4.4); package routes are the defaults. */
  endpoints: Endpoints;
  /** How host responses are unwrapped; default `'raw'`. */
  unwrap?: Unwrap;
  /** Exactly one auth mode, e.g. `userSession({ storage })`. */
  mode: AuthMode;
  /** Refresh this many seconds before expiry (Task 15); default 60. */
  refreshAheadSeconds?: number;
  /** Claim that holds the company id; default `'company_id'`. */
  companyClaim?: string;
  /**
   * Opt-in device headers. When set, every request sends `X-Device-Id` (`id`,
   * else a generated id persisted in the mode's store) and `X-Device-Name` (if `name`).
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
  /** The options passed to `createJwtAuth`. */
  readonly options: Readonly<JwtAuthOptions>;
  /** Request helper (same as `JwtAuth.http`). */
  http<T>(req: HttpRequest): Promise<HttpResult<T>>;
  /** Endpoint lookup (same as `JwtAuth.endpoint`). */
  endpoint(name: keyof Endpoints, module: string): string;
  /** Emits an event to `onEvent`, swallowing hook errors. */
  emit(e: AuthEvent): void;
  /** Unwraps a raw body per `options.unwrap` and finds the token pair; throws `SpAuthError` if none. */
  extractPair(rawBody: unknown, module?: string): TokenPairRaw;
  /** Builds stored `Tokens` from a pair, carrying over non-secret fields (`deviceId`, `csrf`, `lastCompanyId`) from `previous`. */
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
  /** `credentials` applied to login, second-factor and logout calls (cookie transport). */
  readonly credentials?: 'include';
  /** Current access token, or `null`. */
  getAccessToken(): Promise<string | null>;
  /** Auth headers for API calls (`{}` when there is no token). */
  getHeaders(): Promise<Record<string, string>>;
  /** Called on a 401: `true` when the request may be retried. */
  handleUnauthorized(): Promise<boolean>;
  /** Reads persisted state once and resolves `unknown` to `authenticated`/`anonymous`. */
  hydrate?(): Promise<void>;
  /** Unwraps a raw body, stores the pair and updates state. */
  acceptTokens?(rawBody: unknown): Promise<void>;
  /** Clears tokens (keeping `deviceId`) and sets state `anonymous`; no network. */
  clearSession?(): Promise<void>;
  /** Refresh seam (Task 15: single-flight rotation). */
  refresh?(): Promise<void>;
  /** Server-side part of logout, replacing the default; the facade clears the session afterwards regardless. */
  logout?(o?: { everywhere?: boolean }): Promise<void>;
  /** Restores a session from the server (Task 20, cookie transport). */
  restore?(): Promise<void>;
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
  /** Server logout (best effort), then clears storage even if the call failed. */
  logout(o?: { everywhere?: boolean }): Promise<void>;
  /** Current access token or `null`. */
  getAccessToken(): Promise<string | null>;
  /** `{ Authorization: 'Bearer …' }` or `{}`: the `ApiAuth` contract. */
  getHeaders(): Promise<Record<string, string>>;
  /** 401 handler; `true` when the request may be retried once. */
  handleUnauthorized(): Promise<boolean>;
  /** Refreshes now (Task 15); throws `not_configured` when the mode cannot refresh. */
  refresh(): Promise<void>;
  /** Resolves once persisted state has been read (state leaves `unknown`). */
  ready(): Promise<void>;
  /** Stable state snapshot. */
  getState(): AuthState;
  /** Registers a change listener; returns the unsubscribe function. */
  subscribe(l: () => void): () => void;
  /** Decodes `t`, or the current access token's claims when omitted. */
  decodeClaims(t?: string): Claims | null;
  /** Module surface: request helper. */
  http<T>(o: HttpRequest): Promise<HttpResult<T>>;
  /** Module surface: endpoint path; throws `SpAuthError('not_configured', module)` when unset. */
  endpoint(name: keyof Endpoints, module: string): string;
  /** Module surface: unwrap → pair → store → state. */
  acceptTokens(rawBody: unknown): Promise<void>;
  /** Module surface: clears the session without a network call. */
  clearSession(): Promise<void>;
}
