import { decodeClaims } from './claims';
import type { Claims } from './claims';
import { SpAuthError, isSpAuthError } from './errors';
import { createHttp } from './http';
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

/** Package route used by `logout()` when no host `endpoints.logout` is configured. */
export const PACKAGE_REVOKE_PATH = '/auth/token/revoke';

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
 * any session method).
 */
export function createJwtAuth(o: JwtAuthOptions): JwtAuth {
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
      const pair = findTokenPair(unwrap(unwrapMode, rawBody));
      if (!pair) {
        throw new SpAuthError({
          status: 0,
          code: 'unknown',
          message: 'Response did not contain a token pair',
          module,
          body: rawBody,
        });
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

  const acceptTokens = async (rawBody: unknown): Promise<void> => {
    if (!runtime.acceptTokens) throw notConfigured(`acceptTokens for mode '${o.mode.kind}'`, 'core');
    await ready();
    await runtime.acceptTokens(rawBody);
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

  return {
    async login(credentials) {
      const path = endpoint('login', 'login');
      await ready();
      const { body } = await http<unknown>({
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
      await acceptTokens(body);
      emit({ type: 'login' });
      return { status: 'authenticated' };
    },

    async verifySecondFactor(c, code) {
      const path = endpoint('secondFactor', 'secondFactor');
      await ready();
      const build = o.secondFactorBody ?? defaultSecondFactorBody;
      const { body } = await http<unknown>({
        method: 'POST',
        endpoint: path,
        body: build(c, code),
        device: true,
        credentials: runtime.credentials,
        module: 'secondFactor',
      });
      await acceptTokens(body);
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

    getState() {
      void ready();
      return state.get();
    },

    subscribe(l) {
      void ready();
      return state.subscribe(l);
    },

    decodeClaims(t?: string): Claims | null {
      return t === undefined ? state.get().claims : decodeClaims(t);
    },

    http,
    endpoint,
    acceptTokens,
    clearSession,
  };
}
