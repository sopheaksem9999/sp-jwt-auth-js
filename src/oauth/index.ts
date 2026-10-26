import { SpAuthError, isSpAuthError } from '../core/errors';
import { userSession } from '../core/user-session';
import type { UserSessionOptions } from '../core/user-session';
import type { AuthMode, JwtAuth, ModeContext, ModeRuntime } from '../core/types';
import { generateCodeVerifier, pkceChallenge, randomBase64url } from './pkce';

export { generateCodeVerifier, pkceChallenge } from './pkce';

const MODULE = 'oauth';
const PENDING_KEY = 'sp-jwt-auth:oauth:pending';

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function notConfigured(what: string): SpAuthError {
  return new SpAuthError({ status: 0, code: 'not_configured', message: `${what} is not configured`, module: MODULE });
}

function unknownError(message: string, cause?: unknown): SpAuthError {
  // No `body`, and the cause is dropped from the message: a malformed response may carry token values.
  return new SpAuthError({ status: 0, code: 'unknown', message, module: MODULE, cause });
}

/** Raw `id:secret` bytes as Basic credentials, as the backend reads them (`OAuthServerService.php:326-329`, no urldecode). */
function basicHeader(id: string, secret: string): string {
  let bin = '';
  for (const b of new TextEncoder().encode(`${id}:${secret}`)) bin += String.fromCharCode(b);
  return `Basic ${btoa(bin)}`;
}

/** The login in flight: what `beginLogin` persists and `completeLogin` consumes exactly once. */
export interface PendingLogin {
  /** The anti-CSRF `state` sent to the authorize URL. */
  state: string;
  /** The PKCE `code_verifier` whose S256 challenge was sent. */
  verifier: string;
}

/** Where the pending login survives the redirect. A single record: a newer `beginLogin` replaces it. */
export interface PendingStore {
  /** The pending login, or `null`. */
  get(): Promise<PendingLogin | null> | PendingLogin | null;
  /** Saves the pending login; `null` removes it. */
  set(value: PendingLogin | null): Promise<void> | void;
}

interface WebStorage {
  getItem(k: string): string | null;
  setItem(k: string, v: string): void;
  removeItem(k: string): void;
}

function sessionStorageOrNull(): WebStorage | null {
  try {
    const s = (globalThis as { sessionStorage?: WebStorage | null }).sessionStorage;
    return s && typeof s.getItem === 'function' ? s : null;
  } catch {
    return null;
  }
}

function isPending(v: unknown): v is PendingLogin {
  return isRecord(v) && typeof v.state === 'string' && v.state !== '' && typeof v.verifier === 'string' && v.verifier !== '';
}

/**
 * Default pending store: `sessionStorage` when it works (so the record survives
 * the redirect and dies with the tab), every access guarded; a memory copy is
 * kept as well, so a blocked or absent `sessionStorage` still works without a reload.
 */
function defaultPendingStore(): PendingStore {
  let memory: PendingLogin | null = null;
  return {
    get() {
      try {
        const raw = sessionStorageOrNull()?.getItem(PENDING_KEY);
        if (typeof raw === 'string') {
          const v: unknown = JSON.parse(raw);
          if (isPending(v)) return v;
        }
      } catch {
        /* blocked or corrupt: fall back to memory */
      }
      return memory;
    },
    set(value) {
      memory = value;
      try {
        const s = sessionStorageOrNull();
        if (s) {
          if (value === null) s.removeItem(PENDING_KEY);
          else s.setItem(PENDING_KEY, JSON.stringify(value));
        }
      } catch {
        /* the memory copy remains */
      }
    },
  };
}

/** Options for `oauthAuthorizationCode`. */
export interface OAuthAuthorizationCodeOptions {
  /** OAuth client id (a public client in a browser). */
  clientId: string;
  /** The redirect URI registered for the client; sent to the authorize URL and the token request. */
  redirectUri: string;
  /** Requested scope(s); an array is joined with spaces. */
  scope: string | readonly string[];
  /** The host's authorize page (absolute, or a path the app serves). An existing query string is preserved. */
  authorizeUrl: string;
  /** Token URL (absolute, or a path joined to `baseUrl`); default `endpoints.oauthToken` (`/oauth/token`). */
  tokenUrl?: string;
  /** Holds `{ state, verifier }` across the redirect; default `sessionStorage` (feature-detected, guarded), else memory. */
  pendingStore?: PendingStore;
  /**
   * SERVER-SIDE ONLY (a confidential client): when set, the code exchange sends it
   * as HTTP Basic credentials. NEVER put a client secret in browser code; a public
   * browser client uses PKCE alone. It is kept in this closure and never stored, emitted or put in an error.
   */
  clientSecret?: string;
  /** Options for the underlying `userSession` (token `storage`, `transport`, `csrf`, `crossTab`); same defaults. */
  session?: UserSessionOptions;
}

/** The mode returned by `oauthAuthorizationCode`: an `AuthMode` that also carries the login methods. */
export interface OAuthAuthorizationCodeMode extends AuthMode {
  /**
   * Starts a login: generates `state` (256 random bits, base64url) and a PKCE
   * verifier, persists `{ state, verifier }` in the pending store and returns the
   * authorize URL to navigate to. The challenge method is ALWAYS `S256` and always
   * sent (the backend would default an omitted method to `plain`). Rejects
   * `SpAuthError('not_configured')` until the mode has been passed to `createJwtAuth`.
   */
  beginLogin(): Promise<string>;
  /**
   * Finishes a login from the redirect back to `redirectUri`: checks `state`
   * against the pending record, exchanges `code` with the stored verifier at the token
   * URL and stores the pair through the mode (so the refresh token, store and state
   * follow the normal rules). The pending record is cleared on every outcome, so a
   * callback URL is never usable twice. A callback `error` is thrown as
   * `SpAuthError` with `code` = that error (e.g. `access_denied`); a missing or
   * different `state` is `invalid_state`; a missing `code` is `invalid_request`;
   * token endpoint failures carry the RFC 6749 `error` as `code`. On any failure nothing is stored.
   */
  completeLogin(callbackUrl: string): Promise<void>;
}

function authorizeUrlWith(base: string, query: Record<string, string>): string {
  const q = Object.entries(query)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join('&');
  const hash = base.indexOf('#');
  const head = hash === -1 ? base : base.slice(0, hash);
  const tail = hash === -1 ? '' : base.slice(hash);
  const sep = head.includes('?') ? (/[?&]$/.test(head) ? '' : '&') : '?';
  return `${head}${sep}${q}${tail}`;
}

function sameString(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/**
 * OAuth 2.0 authorization-code mode with PKCE, for a client logging users in
 * through the host's `oauth_server` (spec §4.9). Tokens are held by an inner
 * `userSession` (see `options.session`), so refresh, storage, cookie transport and
 * state work as for any user session; only the login differs.
 *
 * ```ts
 * const oauthMode = oauthAuthorizationCode({ clientId, redirectUri, scope: 'read', authorizeUrl });
 * const auth = createJwtAuth({ baseUrl, endpoints: {}, mode: oauthMode });
 * location.assign(await oauthMode.beginLogin());          // go to the host
 * await oauthMode.completeLogin(location.href);           // on the redirect back
 * ```
 *
 * The app holds the returned mode object: `beginLogin` / `completeLogin` are
 * bound to the client once it is created with this mode, and reject
 * `SpAuthError('not_configured')` before that. Use one mode object per client.
 */
export function oauthAuthorizationCode(options: OAuthAuthorizationCodeOptions): OAuthAuthorizationCodeMode {
  const inner = userSession(options.session);
  const pending = options.pendingStore ?? defaultPendingStore();
  const scope = typeof options.scope === 'string' ? options.scope : options.scope.join(' ');
  let bound: { ctx: ModeContext; runtime: ModeRuntime; hydrated: () => Promise<void> } | null = null;

  const requireBound = (): NonNullable<typeof bound> => {
    if (!bound) throw notConfigured('oauthAuthorizationCode (pass the mode to createJwtAuth first)');
    return bound;
  };

  const take = async (): Promise<PendingLogin | null> => {
    let record: PendingLogin | null = null;
    try {
      const v = await pending.get();
      record = isPending(v) ? v : null;
    } catch {
      record = null;
    }
    try {
      await pending.set(null); // single use, whatever happens next
    } catch {
      /* a store that cannot clear is the app's problem; the record was read once here */
    }
    return record;
  };

  const complete = async (callbackUrl: string): Promise<void> => {
    const { ctx, runtime, hydrated } = requireBound();
    const record = await take();
    let url: URL;
    try {
      url = new URL(callbackUrl, 'http://localhost');
    } catch {
      throw new SpAuthError({ status: 0, code: 'invalid_request', message: 'Callback URL is not valid', module: MODULE });
    }
    const q = url.searchParams;
    const state = q.get('state');
    if (record === null || state === null || !sameString(state, record.state)) {
      throw new SpAuthError({
        status: 0,
        code: 'invalid_state',
        message: 'Login callback state is missing or does not match the pending login',
        module: MODULE,
      });
    }
    const error = q.get('error');
    if (error !== null && error !== '') {
      const description = (q.get('error_description') ?? '').slice(0, 300);
      throw new SpAuthError({
        status: 0,
        code: error,
        message: description !== '' ? description : `Authorization failed: ${error}`,
        module: MODULE,
      });
    }
    const code = q.get('code');
    if (code === null || code === '') {
      throw new SpAuthError({ status: 0, code: 'invalid_request', message: 'Login callback has no authorization code', module: MODULE });
    }

    const form: Record<string, string> = {
      grant_type: 'authorization_code',
      code,
      redirect_uri: options.redirectUri,
      client_id: options.clientId,
      code_verifier: record.verifier,
    };
    const headers: Record<string, string> = {};
    if (options.clientSecret !== undefined && options.clientSecret !== '') {
      headers.Authorization = basicHeader(options.clientId, options.clientSecret);
    }
    const { body, response } = await ctx.http<unknown>({
      method: 'POST',
      endpoint: options.tokenUrl ?? ctx.endpoint('oauthToken', MODULE),
      form,
      headers,
      device: true,
      credentials: runtime.credentials,
      module: MODULE,
      disabledOn404: true,
    });
    try {
      await hydrated();
      await runtime.acceptTokens?.(body, response);
    } catch (e) {
      if (isSpAuthError(e) && e.code !== 'unknown') throw e;
      throw unknownError('Token response could not be accepted', e);
    }
    ctx.emit({ type: 'login', oauth: true });
  };

  // One completion at a time, so two copies of a callback cannot both read the pending record.
  let chain: Promise<unknown> = Promise.resolve();

  return {
    kind: 'oauthAuthorizationCode',
    create(ctx) {
      const runtime = inner.create(ctx);
      // Memoised so the facade's own `ready()` and `completeLogin` share one hydration.
      let hydration: Promise<void> | null = null;
      const hydrated = (): Promise<void> => (hydration ??= Promise.resolve(runtime.hydrate?.()).catch(() => undefined));
      bound = { ctx, runtime, hydrated };
      return { ...runtime, hydrate: hydrated };
    },

    async beginLogin() {
      requireBound();
      const state = randomBase64url(32);
      const verifier = generateCodeVerifier();
      const challenge = await pkceChallenge(verifier);
      await pending.set({ state, verifier });
      return authorizeUrlWith(options.authorizeUrl, {
        response_type: 'code',
        client_id: options.clientId,
        redirect_uri: options.redirectUri,
        scope,
        state,
        code_challenge: challenge,
        code_challenge_method: 'S256',
      });
    },

    completeLogin(callbackUrl) {
      const run = chain.then(() => complete(callbackUrl));
      chain = run.catch(() => undefined);
      return run;
    },
  };
}

/** Client credentials for `oauth(auth, creds)`. SERVER-SIDE ONLY: a secret must never reach a browser. */
export interface OAuthClientCredentials {
  clientId: string;
  clientSecret: string;
  /** `'basic'` (default, `Authorization: Basic …`) or `'body'` (`client_id` / `client_secret` form fields). */
  auth?: 'basic' | 'body';
}

/** Token introspection result (RFC 7662, plus the legacy camelCase shape). Inactive tokens are only `{ active: false }`. */
export interface Introspection {
  active: boolean;
  clientId?: string;
  userId?: string;
  scopes?: string[];
  /** Expiry; `null` when the token reports none. */
  expiresAt?: Date | null;
  tokenId?: string;
}

/** The `oauth(auth)` module surface. */
export interface OAuthModule {
  /** POSTs the token to `endpoints.oauthIntrospect` (default `/oauth/introspect`), authenticated as the client; only that client's tokens are reported active. */
  introspect(token: string): Promise<Introspection>;
  /** POSTs the token to `endpoints.oauthRevoke` (default `/oauth/revoke`) (RFC 7009: an unknown token is not an error). `hint` picks the token type. */
  revoke(token: string, hint?: 'access_token' | 'refresh_token'): Promise<void>;
}

function str(v: unknown): string | undefined {
  return typeof v === 'string' && v !== '' ? v : undefined;
}

function toDate(v: unknown): Date | null {
  let d: Date | null = null;
  if (typeof v === 'number' && Number.isFinite(v)) d = new Date(v * 1000);
  else if (typeof v === 'string' && v !== '') d = new Date(v);
  return d !== null && !Number.isNaN(d.getTime()) ? d : null;
}

function mapIntrospection(body: Record<string, unknown>): Introspection {
  if (body.active !== true) return { active: false };
  const out: Introspection = { active: true };
  const clientId = str(body.client_id) ?? str(body.clientId);
  const userId = str(body.sub) ?? str(body.userId);
  const tokenId = str(body.jti) ?? str(body.tokenId);
  if (clientId !== undefined) out.clientId = clientId;
  if (userId !== undefined) out.userId = userId;
  if (typeof body.scope === 'string') out.scopes = body.scope.split(/\s+/).filter((s) => s !== '');
  else if (Array.isArray(body.scopes)) out.scopes = body.scopes.filter((s): s is string => typeof s === 'string');
  out.expiresAt = toDate(body.exp ?? body.expiresAt);
  if (tokenId !== undefined) out.tokenId = tokenId;
  return out;
}

/**
 * OAuth server extras: token introspection and revocation (backend
 * `oauth_server`, `routes/oauth.php` `/introspect` and `/revoke`; **off by default**,
 * a 404 is `SpAuthError('module_disabled')`).
 *
 * Both calls authenticate as an OAuth client (HTTP Basic, or `client_id` /
 * `client_secret` in the form) and only affect that client's tokens. That
 * makes them **server-side only**: never pass a client secret from browser code.
 * Without `creds`, calls reject `SpAuthError('not_configured')` (the secret of a
 * `clientCredentials` mode is deliberately not reachable from here).
 *
 * @param auth The client from `createJwtAuth`.
 * @param creds The OAuth client credentials.
 */
export function oauth(auth: JwtAuth, creds?: OAuthClientCredentials): OAuthModule {
  const call = async (name: 'oauthIntrospect' | 'oauthRevoke', fields: Record<string, string>): Promise<unknown> => {
    if (!creds || typeof creds.clientId !== 'string' || creds.clientId === '' || typeof creds.clientSecret !== 'string' || creds.clientSecret === '') {
      throw notConfigured('oauth client credentials');
    }
    const endpoint = auth.endpoint(name, MODULE);
    const form = { ...fields };
    const headers: Record<string, string> = {};
    if ((creds.auth ?? 'basic') === 'basic') headers.Authorization = basicHeader(creds.clientId, creds.clientSecret);
    else {
      form.client_id = creds.clientId;
      form.client_secret = creds.clientSecret;
    }
    const { body } = await auth.http<unknown>({
      method: 'POST',
      endpoint,
      form,
      headers,
      bearer: false,
      module: MODULE,
      disabledOn404: true,
    });
    return body;
  };

  return {
    async introspect(token) {
      const raw = await call('oauthIntrospect', { token });
      let unwrapped: unknown;
      try {
        unwrapped = auth.unwrap(raw);
      } catch (cause) {
        throw unknownError('Response could not be unwrapped', cause);
      }
      // The package routes are not enveloped; when the configured unwrap hides `active`, the raw body is tried.
      const body = [unwrapped, raw].find((b): b is Record<string, unknown> => isRecord(b) && typeof b.active === 'boolean');
      if (!body) throw unknownError('Response was not a token introspection');
      return mapIntrospection(body);
    },

    async revoke(token, hint) {
      await call('oauthRevoke', hint === undefined ? { token } : { token, token_type_hint: hint });
    },
  };
}
