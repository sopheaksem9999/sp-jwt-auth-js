import { SpAuthError, isSpAuthError, sanitizedCause } from '../core/errors';
import { userSession } from '../core/user-session';
import type { UserSessionOptions } from '../core/user-session';
import type { AuthMode, JwtAuth, ModeContext, ModeRuntime } from '../core/types';
import { generateCodeVerifier, pkceChallenge, randomBase64url } from './pkce';

export { generateCodeVerifier, pkceChallenge } from './pkce';

const MODULE = 'oauth';
/** Default pending-store key prefix; the client id is appended, so two clients on one origin do not share records. */
const PENDING_KEY = 'sp-jwt-auth:oauth:pending';
/** A started login older than this (seconds) is dropped when the pending store is read. */
const PENDING_TTL_SECONDS = 600;
/** At most this many unfinished logins are kept; the oldest are dropped first. */
const PENDING_MAX = 20;

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function notConfigured(what: string): SpAuthError {
  return new SpAuthError({ status: 0, code: 'not_configured', message: `${what} is not configured`, module: MODULE });
}

function unknownError(message: string, cause?: unknown): SpAuthError {
  // No `body`, and the cause is reduced to name/status/code: a malformed response may carry token values and loggers print `cause`.
  return new SpAuthError({ status: 0, code: 'unknown', message, module: MODULE, cause: sanitizedCause(cause) });
}

/** Raw `id:secret` bytes as Basic credentials, as the backend reads them (`OAuthServerService.php:326-329`, no urldecode). */
function basicHeader(id: string, secret: string): string {
  let bin = '';
  for (const b of new TextEncoder().encode(`${id}:${secret}`)) bin += String.fromCharCode(b);
  return `Basic ${btoa(bin)}`;
}

/** One login in flight: the PKCE verifier and when `beginLogin` ran (epoch seconds). */
export interface PendingEntry {
  /** The PKCE `code_verifier` whose S256 challenge was sent. */
  verifier: string;
  /** When the login was started, epoch seconds; entries older than 10 minutes are pruned. */
  createdAt: number;
}

/** Everything the pending store holds: the logins in flight, keyed by their `state`. */
export type PendingLogins = Record<string, PendingEntry>;

/**
 * Where the logins in flight survive the redirect: one value holding a map
 * keyed by `state`, so two logins started in the same tab or session do not
 * invalidate each other. On a server, give each user's own session-backed store
 * (see the README); a store shared between users would let them see each other's verifiers.
 *
 * `completeLogin` removes the callback's entry with `set`; a custom store whose
 * `set` throws leaves that entry in place, so its callback URL could be replayed
 * until it expires. Make `set` reliable.
 */
export interface PendingStore {
  /** The pending logins, or `null`. */
  get(): Promise<PendingLogins | null> | PendingLogins | null;
  /** Saves the pending logins; `null` removes everything. */
  set(value: PendingLogins | null): Promise<void> | void;
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

function isEntry(v: unknown): v is PendingEntry {
  return isRecord(v) && typeof v.verifier === 'string' && v.verifier !== '' && typeof v.createdAt === 'number';
}

function asLogins(v: unknown): PendingLogins {
  const out: PendingLogins = {};
  if (!isRecord(v)) return out;
  for (const [state, entry] of Object.entries(v)) if (isEntry(entry)) out[state] = { verifier: entry.verifier, createdAt: entry.createdAt };
  return out;
}

/**
 * Default pending store, under `sp-jwt-auth:oauth:pending:<clientId>`:
 * `sessionStorage` when it works (so the records survive the redirect and die
 * with the tab), every access guarded; a memory copy is kept as well, so a blocked
 * or absent `sessionStorage` still works without a reload. On a server there is no
 * `sessionStorage`, so this is one in-memory slot: pass a per-user `pendingStore` there.
 */
function defaultPendingStore(clientId: string): PendingStore {
  const key = `${PENDING_KEY}:${clientId}`;
  let memory: PendingLogins | null = null;
  return {
    get() {
      try {
        const raw = sessionStorageOrNull()?.getItem(key);
        if (typeof raw === 'string') return asLogins(JSON.parse(raw));
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
          if (value === null) s.removeItem(key);
          else s.setItem(key, JSON.stringify(value));
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
  /**
   * Holds the logins in flight across the redirect, as one map keyed by `state`
   * (`{ [state]: { verifier, createdAt } }`, see `PendingLogins`); default
   * `sessionStorage` (feature-detected, guarded), else memory.
   */
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
   * verifier, adds `{ verifier, createdAt }` under that `state` to the pending-store
   * map (other logins in flight are kept) and returns the
   * authorize URL to navigate to. The challenge method is ALWAYS `S256` and always
   * sent (the backend would default an omitted method to `plain`). Rejects
   * `SpAuthError('not_configured')` until the mode has been passed to `createJwtAuth`.
   */
  beginLogin(): Promise<string>;
  /**
   * Finishes a login from the redirect back to `redirectUri`: checks `state`
   * against the pending record, exchanges `code` with the stored verifier at the token
   * URL and stores the pair through the mode (so the refresh token, store and state
   * follow the normal rules). The callback's pending entry (looked up by `state`) is
   * consumed on every outcome, so a callback URL is never usable twice; other logins in flight are untouched. A callback `error` is thrown as
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

/** RFC 6749 §5.2 `error`: `%x20-21 / %x23-5B / %x5D-7E`, at most 64 characters. */
const ERROR_CODE = /^[\x20\x21\x23-\x5B\x5D-\x7E]{1,64}$/;
/** Same charset for `error_description`, at most 300 characters. */
const ERROR_DESCRIPTION = /^[\x20\x21\x23-\x5B\x5D-\x7E]{1,300}$/;

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
 * `SpAuthError('not_configured')` before that. **One mode object per client**: a second
 * `createJwtAuth` with the same mode throws `not_configured` (unless the first client was
 * `dispose()`d). A server must build the mode per user or request, with a `pendingStore`
 * backed by that user's server session.
 */
export function oauthAuthorizationCode(options: OAuthAuthorizationCodeOptions): OAuthAuthorizationCodeMode {
  const inner = userSession(options.session);
  const pending = options.pendingStore ?? defaultPendingStore(options.clientId);
  const scope = typeof options.scope === 'string' ? options.scope : options.scope.join(' ');
  let bound: { ctx: ModeContext; runtime: ModeRuntime; hydrated: () => Promise<void>; disposed: boolean } | null = null;

  const requireBound = (): NonNullable<typeof bound> => {
    if (!bound) throw notConfigured('oauthAuthorizationCode (pass the mode to createJwtAuth first)');
    return bound;
  };

  /** Pending logins with the expired and surplus ones removed (oldest first). */
  const readLogins = async (nowSeconds: number): Promise<PendingLogins> => {
    let raw: unknown = null;
    try {
      raw = await pending.get();
    } catch {
      raw = null;
    }
    const live = Object.entries(asLogins(raw)).filter(([, v]) => nowSeconds - v.createdAt < PENDING_TTL_SECONDS);
    live.sort((a, b) => a[1].createdAt - b[1].createdAt);
    return Object.fromEntries(live.slice(-PENDING_MAX));
  };

  const writeLogins = async (logins: PendingLogins): Promise<void> => {
    await pending.set(Object.keys(logins).length === 0 ? null : logins);
  };

  /** Removes and returns the entry for `state` (single use); expired entries are pruned in the same write. */
  const take = async (nowSeconds: number, state: string | null): Promise<PendingEntry | null> => {
    const logins = await readLogins(nowSeconds);
    let found: PendingEntry | null = null;
    if (state !== null && Object.prototype.hasOwnProperty.call(logins, state)) {
      found = logins[state] ?? null;
      delete logins[state];
    }
    try {
      await writeLogins(logins);
    } catch {
      /* a store that cannot save is the app's problem; see PendingStore */
    }
    return found;
  };

  const complete = async (callbackUrl: string): Promise<void> => {
    const { ctx, runtime, hydrated } = requireBound();
    let url: URL | null = null;
    try {
      url = new URL(callbackUrl, 'http://localhost');
    } catch {
      url = null;
    }
    const q = url?.searchParams ?? new URLSearchParams();
    const state = q.get('state');
    // Consumed before anything else can fail, so this state is never usable again.
    const record = await take(ctx.now(), state === '' ? null : state);
    if (url === null) {
      throw new SpAuthError({ status: 0, code: 'invalid_request', message: 'Callback URL is not valid', module: MODULE });
    }
    if (record === null || state === null) {
      throw new SpAuthError({
        status: 0,
        code: 'invalid_state',
        message: 'Login callback state is missing or does not match a pending login',
        module: MODULE,
      });
    }
    const error = q.get('error');
    if (error !== null && error !== '') {
      // Attacker-controlled text: only a well-formed RFC 6749 §5.2 code is surfaced, and nothing invalid is echoed.
      if (!ERROR_CODE.test(error)) {
        throw new SpAuthError({ status: 0, code: 'invalid_request', message: 'Login callback carried an invalid error value', module: MODULE });
      }
      const description = q.get('error_description') ?? '';
      throw new SpAuthError({
        status: 0,
        code: error,
        message: ERROR_DESCRIPTION.test(description) ? description : `Authorization failed: ${error}`,
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
    } catch {
      /* the facade's ready() handles a failed hydration; the login can still proceed */
    }
    try {
      await runtime.acceptTokens?.(body, response);
    } catch (e) {
      // Core errors for an invalid pair carry no body or raw cause; anything else is reduced to a fixed message.
      if (isSpAuthError(e)) throw e;
      throw unknownError('Token response could not be accepted', e);
    }
    ctx.emit({ type: 'login', oauth: true });
  };

  // One begin/complete at a time: the pending value is read-modify-write, and two copies of a callback must exchange once.
  let chain: Promise<unknown> = Promise.resolve();
  const serial = <T>(fn: () => Promise<T>): Promise<T> => {
    const run = chain.then(fn);
    chain = run.catch(() => undefined);
    return run;
  };

  return {
    kind: 'oauthAuthorizationCode',
    create(ctx) {
      if (bound && !bound.disposed) {
        throw new SpAuthError({
          status: 0,
          code: 'not_configured',
          message: 'oauthAuthorizationCode mode is already attached to a client; create one mode per client/request',
          module: MODULE,
        });
      }
      const runtime = inner.create(ctx);
      // Memoised so the facade's own `ready()` and `completeLogin` share one hydration. A failure is rethrown to the facade.
      let hydration: Promise<void> | null = null;
      const hydrated = (): Promise<void> => (hydration ??= Promise.resolve().then(() => runtime.hydrate?.()));
      const me = { ctx, runtime, hydrated, disposed: false };
      bound = me;
      return {
        ...runtime,
        hydrate: hydrated,
        dispose() {
          me.disposed = true;
          runtime.dispose?.();
        },
      };
    },

    beginLogin() {
      return serial(async () => {
        const { ctx } = requireBound();
        const state = randomBase64url(32);
        const verifier = generateCodeVerifier();
        const challenge = await pkceChallenge(verifier);
        const nowSeconds = ctx.now();
        const logins = await readLogins(nowSeconds);
        logins[state] = { verifier, createdAt: nowSeconds };
        await writeLogins(logins);
        return authorizeUrlWith(options.authorizeUrl, {
          response_type: 'code',
          client_id: options.clientId,
          redirect_uri: options.redirectUri,
          scope,
          state,
          code_challenge: challenge,
          code_challenge_method: 'S256',
        });
      });
    },

    completeLogin(callbackUrl) {
      return serial(() => complete(callbackUrl));
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
