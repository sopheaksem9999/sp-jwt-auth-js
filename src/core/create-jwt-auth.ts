import { decodeClaims } from './claims';
import type { Claims } from './claims';
import { SpAuthError, isSpAuthError, sanitizedCause } from './errors';
import { PACKAGE_REVOKE_PATH, createHttp } from './http';
import { ANONYMOUS_STATE, authenticatedState, createState } from './state';
import { ensureDeviceId } from './stores';
import type { Tokens } from './stores';
import type {
  AuthEvent,
  Challenge,
  Endpoints,
  JwtAuth,
  JwtAuthOptions,
  LoginResult,
  ModeContext,
  ModeRuntime,
} from './types';
import { detectChallenge, findTokenPair, unwrap } from './unwrap';
import type { TokenPairRaw } from './unwrap';

export type {
  AuthEvent,
  AuthMode,
  Challenge,
  Endpoints,
  JwtAuth,
  JwtAuthOptions,
  LoginResult,
  ModeContext,
  ModeRuntime,
  UnauthorizedContext,
} from './types';
export type { AuthState } from './state';
export type { HttpRequest, HttpResult } from './http';
export { userSession } from './user-session';
export type { UserSessionOptions } from './user-session';

/** Package defaults for endpoints that have one (spec §4.4). */
export const DEFAULT_ENDPOINTS = {
  refresh: '/auth/token/refresh',
  otp: '/otp',
  oauthToken: '/oauth/token',
  oauthIntrospect: '/oauth/introspect',
  oauthRevoke: '/oauth/revoke',
  jwks: '/.well-known/sp-jwt-auth/jwks.json',
} as const satisfies Partial<Endpoints>;

export { PACKAGE_REVOKE_PATH } from './http';

/** Default second-factor body: `{ '2fa_token', otp }` or `{ challenge_id, code }`. */
export function defaultSecondFactorBody(c: Challenge, code: string): Record<string, unknown> {
  return c.kind === '2fa_token' ? { '2fa_token': c.token, otp: code } : { challenge_id: c.token, code };
}

function notConfigured(what: string, module: string): SpAuthError {
  return new SpAuthError({ status: 0, code: 'not_configured', message: `${what} is not configured`, module });
}

/**
 * Creates the auth client. State starts `unknown` and is resolved lazily from
 * the mode's storage (first call to `ready()`, `getState()`, `subscribe()` or
 * any session method). `endpoints` may be omitted (`{}`: package routes only).
 */
export function createJwtAuth(options: JwtAuthOptions): JwtAuth {
  const o: JwtAuthOptions & { endpoints: Endpoints } = { ...options, endpoints: options.endpoints ?? {} };
  const unwrapMode = o.unwrap ?? 'raw';
  const companyClaim = o.companyClaim ?? 'company_id';
  const state = createState();

  const emit = (e: AuthEvent): void => {
    try {
      o.onEvent?.(e);
    } catch {
      /* hooks never propagate */
    }
  };

  const endpoint = (name: keyof Endpoints, module: string): string => {
    const configured = o.endpoints[name];
    if (typeof configured === 'string' && configured !== '') return configured;
    const fallback = (DEFAULT_ENDPOINTS as Partial<Endpoints>)[name];
    if (fallback !== undefined) return fallback;
    throw notConfigured(`endpoints.${name}`, module);
  };

  const http = createHttp({
    baseUrl: o.baseUrl,
    fetch: o.fetch,
    timeoutMs: o.timeoutMs,
    async deviceHeaders() {
      if (!o.device) return {};
      const h: Record<string, string> = {};
      const id = o.device.id ?? (runtime.store ? await ensureDeviceId(runtime.store) : undefined);
      if (id) h['X-Device-Id'] = id;
      if (o.device.name) h['X-Device-Name'] = o.device.name;
      return h;
    },
    authHeaders: () => runtime.getHeaders(),
  });

  const now = (): number => Math.floor(Date.now() / 1000);

  const ctx: ModeContext = {
    options: o,
    http,
    endpoint,
    emit,
    extractPair(rawBody: unknown, module?: string): TokenPairRaw {
      // Never `body` or the raw cause on these errors: the rejected response may still hold token values, and loggers print `cause`.
      let unwrapped: unknown;
      try {
        unwrapped = unwrap(unwrapMode, rawBody);
      } catch (e) {
        throw new SpAuthError({
          status: 0,
          code: 'unknown',
          message: 'Response could not be unwrapped',
          module,
          cause: sanitizedCause(e),
        });
      }
      const pair = findTokenPair(unwrapped);
      if (!pair) {
        throw new SpAuthError({ status: 0, code: 'unknown', message: 'Response did not contain a token pair', module });
      }
      return pair;
    },
    tokensFromPair(pair: TokenPairRaw, previous: Tokens | null): Tokens {
      const t: Tokens = { accessToken: pair.access_token };
      if (pair.refresh_token) t.refreshToken = pair.refresh_token;
      // Spec §4.5: JWT exp first, falling back to expires_in (opaque tokens). 0 means absent for both.
      const exp = decodeClaims(pair.access_token)?.exp;
      if (typeof exp === 'number' && exp > 0) t.expiresAt = exp;
      else if (pair.expires_in > 0) t.expiresAt = now() + pair.expires_in;
      if (previous?.deviceId) t.deviceId = previous.deviceId;
      if (previous?.csrf) t.csrf = previous.csrf;
      if (previous?.lastCompanyId) t.lastCompanyId = previous.lastCompanyId;
      return t;
    },
    getState: () => state.get(),
    setAuthenticated: (accessToken) => state.set(authenticatedState(accessToken, companyClaim, state.get())),
    setAnonymous: () => state.set(ANONYMOUS_STATE),
    now,
  };

  // Declared after ctx: the closures above only read `runtime` once requests run.
  const runtime: ModeRuntime = o.mode.create(ctx);

  let readyPromise: Promise<void> | null = null;
  const ready = (): Promise<void> => {
    if (!readyPromise) {
      readyPromise = (async () => {
        try {
          await runtime.hydrate?.();
        } catch {
          if (state.get().status === 'unknown') state.set(ANONYMOUS_STATE);
        }
      })();
    }
    return readyPromise;
  };

  const acceptTokens = async (rawBody: unknown, response?: Response): Promise<void> => {
    if (!runtime.acceptTokens) throw notConfigured(`acceptTokens for mode '${o.mode.kind}'`, 'core');
    await ready();
    await runtime.acceptTokens(rawBody, response);
  };

  const clearSession = async (): Promise<void> => {
    await ready();
    if (runtime.clearSession) await runtime.clearSession();
    else state.set(ANONYMOUS_STATE);
  };

  const defaultServerLogout = async (everywhere: boolean, accessToken: string | null): Promise<void> => {
    const host = o.endpoints.logout;
    if (!host && !accessToken) return; // nothing to revoke
    await http({
      method: 'POST',
      endpoint: host || PACKAGE_REVOKE_PATH,
      body: host && everywhere ? { everywhere: true } : undefined,
      headers: accessToken ? { Authorization: `Bearer ${accessToken}` } : undefined,
      credentials: runtime.credentials,
      module: 'logout',
    });
  };

  /** Auth headers for a request: the (proactively refreshed) access token, or none. */
  const bearerHeaders = async (): Promise<Record<string, string>> => {
    const token = await runtime.getAccessToken();
    return token ? { Authorization: `Bearer ${token}` } : {};
  };

  const hasScopeIn = (held: readonly string[], scope: string): boolean => held.includes('*') || held.includes(scope);
  const heldScopes = (): readonly string[] | null => {
    void ready();
    return state.get().claims?.scopes ?? null;
  };

  return {
    async login(credentials) {
      const path = endpoint('login', 'login');
      await ready();
      const { body, response } = await http<unknown>({
        method: 'POST',
        endpoint: path,
        body: credentials,
        device: true,
        credentials: runtime.credentials,
        module: 'login',
      });
      const challenge = detectChallenge(body);
      if (challenge) {
        // Detected on the RAW body (before unwrap); nothing is stored.
        const result: LoginResult = { status: 'second_factor_required', challenge };
        return result;
      }
      await acceptTokens(body, response);
      emit({ type: 'login' });
      return { status: 'authenticated' };
    },

    async verifySecondFactor(c, code) {
      const path = endpoint('secondFactor', 'secondFactor');
      await ready();
      const build = o.secondFactorBody ?? defaultSecondFactorBody;
      const { body, response } = await http<unknown>({
        method: 'POST',
        endpoint: path,
        body: build(c, code),
        device: true,
        credentials: runtime.credentials,
        module: 'secondFactor',
      });
      await acceptTokens(body, response);
      emit({ type: 'login', secondFactor: true });
    },

    async logout(opts) {
      await ready();
      const everywhere = opts?.everywhere === true;
      // Capture without refreshing: a refresh here would rotate tokens we are about to revoke.
      let accessToken: string | null = null;
      try {
        accessToken = runtime.peekAccessToken ? await runtime.peekAccessToken() : await runtime.getAccessToken();
      } catch {
        accessToken = null;
      }
      // Local state goes first, so the app is logged out even if the network call hangs.
      try {
        await clearSession();
      } catch {
        state.set(ANONYMOUS_STATE);
      }
      let remoteError: unknown;
      try {
        if (runtime.logout) await runtime.logout({ everywhere, accessToken });
        else await defaultServerLogout(everywhere, accessToken);
      } catch (e) {
        // 401 = already logged out; anything else is reported on the event, never thrown.
        if (!(isSpAuthError(e) && e.status === 401)) remoteError = e;
      }
      emit(remoteError === undefined ? { type: 'logout', everywhere } : { type: 'logout', everywhere, remoteError });
    },

    async getAccessToken(opts) {
      await ready();
      return runtime.getAccessToken(opts);
    },

    async getHeaders() {
      await ready();
      return runtime.getHeaders();
    },

    async handleUnauthorized(opts) {
      await ready();
      return runtime.handleUnauthorized(opts);
    },

    async refresh() {
      if (!runtime.refresh) throw notConfigured(`refresh for mode '${o.mode.kind}'`, 'core');
      await ready();
      await runtime.refresh();
    },

    ready,

    async restore() {
      await ready();
      await runtime.restore?.();
    },

    getState() {
      void ready();
      return state.get();
    },

    subscribe(l) {
      void ready();
      return state.subscribe(l);
    },

    async whoami() {
      const path = endpoint('whoami', 'core');
      await ready();
      const get = async (headers: Record<string, string>): Promise<unknown> =>
        (await http<unknown>({ method: 'GET', endpoint: path, headers, credentials: runtime.credentials, module: 'whoami' })).body;
      let headers = await bearerHeaders();
      // The subject the request is sent for: a login as someone else meanwhile must not get this user.
      let subject = state.get().claims?.sub;
      let body: unknown;
      try {
        body = await get(headers);
      } catch (e) {
        if (!(isSpAuthError(e) && e.status === 401) || !(await runtime.handleUnauthorized({ headers }))) throw e;
        // Retried once with the refreshed token; a second 401 is the caller's.
        headers = await bearerHeaders();
        subject = state.get().claims?.sub;
        body = await get(headers);
      }
      const user = unwrap(unwrapMode, body);
      const current = state.get();
      if (current.status === 'authenticated' && current.claims?.sub === subject) state.set({ ...current, user });
      return user;
    },

    async switchCompany(companyId) {
      const path = endpoint('switchCompany', 'core');
      await ready();
      // Proactive refresh first (it takes the lock itself); the call below must not refresh while holding it.
      await runtime.getAccessToken();
      const run = async (): Promise<void> => {
        const body = runtime.switchCompanyBody
          ? await runtime.switchCompanyBody(companyId)
          : { company_id: companyId };
        const stored = runtime.peekAccessToken ? await runtime.peekAccessToken() : null;
        const headers: Record<string, string> = runtime.tokenRequestHeaders ? await runtime.tokenRequestHeaders() : {};
        if (stored) headers.Authorization = `Bearer ${stored}`;
        const send = (h: Record<string, string>) =>
          http<unknown>({
            method: 'POST',
            endpoint: path,
            body,
            device: true,
            headers: h,
            credentials: runtime.credentials,
            module: 'switchCompany',
          });
        let result: Awaited<ReturnType<typeof send>>;
        try {
          result = await send(headers);
        } catch (e) {
          // Cookie transport: a stale CSRF value is retried once with the live cookie value.
          const retry = isSpAuthError(e) && e.status === 403 && runtime.recoverCsrfHeaders ? await runtime.recoverCsrfHeaders(headers) : null;
          if (retry === null) throw e;
          result = await send(retry);
        }
        const { body: raw, response } = result;
        // Validates the pair before anything is stored: an invalid response keeps the current tokens.
        // No `body` on the error in any transport: a rejected response may still carry token values.
        ctx.extractPair(raw, 'switchCompany');
        await acceptTokens(raw, response);
        const store = runtime.store;
        if (store) {
          const t = await store.get();
          if (t) await store.set({ ...t, lastCompanyId: String(companyId) });
        }
      };
      if (runtime.withRefreshLock) await runtime.withRefreshLock(run);
      else await run();
    },

    hasScope(scope) {
      const held = heldScopes();
      return held !== null && hasScopeIn(held, scope);
    },

    hasAllScopes(scopes) {
      const held = heldScopes();
      return held !== null && scopes.every((s) => hasScopeIn(held, s));
    },

    hasAnyScope(scopes) {
      const held = heldScopes();
      return held !== null && scopes.some((s) => hasScopeIn(held, s));
    },

    decodeClaims(t?: string): Claims | null {
      return t === undefined ? state.get().claims : decodeClaims(t);
    },

    baseUrl: o.baseUrl,
    credentials: runtime.credentials,
    unwrap: (body) => unwrap(unwrapMode, body),
    http,
    endpoint,
    acceptTokens,
    clearSession,

    dispose() {
      try {
        runtime.dispose?.();
      } catch {
        /* disposal never throws */
      }
    },
  };
}
