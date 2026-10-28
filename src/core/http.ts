import { SpAuthError, authErrorFromResponse, sanitizedCause } from './errors';
import type { AuthRequestLogger } from './log-types';

/** Options for one request made through `JwtAuth.http`. */
export interface HttpRequest {
  method: string;
  /** Path joined to `baseUrl`, or a full `http(s)://` URL used as is. */
  endpoint: string;
  /** Sent as JSON (with `Content-Type: application/json`) when not `undefined`. */
  body?: unknown;
  /**
   * Sent as `application/x-www-form-urlencoded` (OAuth token requests). Mutually
   * exclusive with `body`; when both are set, `form` wins.
   */
  form?: Record<string, string>;
  /** Adds the mode's auth headers (`Authorization: Bearer …`). */
  bearer?: boolean;
  /**
   * Sends the device headers (`X-Device-Id`/`X-Device-Name`, when the `device`
   * option is set). Only token-issuing calls (login, second factor, refresh) set
   * this; the headers are never sent to an origin other than `baseUrl`'s.
   */
  device?: boolean;
  credentials?: 'include';
  headers?: Record<string, string>;
  signal?: AbortSignal;
  /** Module name stamped on any `SpAuthError` thrown. */
  module?: string;
  /** A 404 means the module's route is switched off: it throws `SpAuthError('module_disabled')`. */
  disabledOn404?: boolean;
}

/** Token from an `Authorization: Bearer …` header (header name and scheme case-insensitive), or `null`. */
export function bearerFrom(headers: Record<string, string> | undefined): string | null {
  if (!headers) return null;
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() !== 'authorization') continue;
    const m = /^\s*bearer\s+(\S+)\s*$/i.exec(v);
    return m?.[1] ?? null;
  }
  return null;
}

/** Successful response: parsed JSON body (`null` when empty, the text when not JSON) and the consumed `Response`. */
export interface HttpResult<T> {
  body: T;
  response: Response;
}

/** Collaborators the HTTP helper needs; resolved lazily per request. */
export interface HttpDeps {
  baseUrl: string;
  fetch?: typeof fetch;
  timeoutMs?: number;
  /** Device headers (`X-Device-Id`/`X-Device-Name`), or `{}` when the device option is off. */
  deviceHeaders(): Promise<Record<string, string>>;
  /** Auth headers for `bearer: true`. */
  authHeaders(): Promise<Record<string, string>>;
  /** Request logger from `@sokpheak/sp-jwt-auth/logging`; used only when `logRequests === true`. */
  logger?: AuthRequestLogger;
  logRequests?: boolean;
}

/** Package route used by `logout()` when no host `endpoints.logout` is configured. */
export const PACKAGE_REVOKE_PATH = '/auth/token/revoke';

/** Default request timeout in milliseconds. */
export const DEFAULT_TIMEOUT_MS = 60_000;

const ABSOLUTE_URL = /^https?:\/\//i;

/** Joins `endpoint` onto `baseUrl` (trailing slashes stripped); full http(s) URLs pass through. */
export function resolveUrl(baseUrl: string, endpoint: string): string {
  if (ABSOLUTE_URL.test(endpoint)) return endpoint;
  const base = baseUrl.replace(/\/+$/, '');
  return base + (endpoint.startsWith('/') ? endpoint : `/${endpoint}`);
}

function originOf(url: string): string | null {
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
}

/** `true` when `url` (already resolved) has the same origin as `baseUrl`. */
export function sameOrigin(baseUrl: string, url: string): boolean {
  const a = originOf(baseUrl);
  return a !== null && a === originOf(url);
}

function parseBody(text: string): unknown {
  if (text === '') return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

/**
 * Creates the request function behind `JwtAuth.http`. Caller abort rethrows the
 * caller's reason; the timeout throws `SpAuthError('timeout')`; any other fetch
 * rejection throws `SpAuthError('network')` (both with a `cause` that keeps only the
 * rejection's `name`); non-2xx throws via `authErrorFromResponse`.
 */
export function createHttp(deps: HttpDeps): <T>(req: HttpRequest) => Promise<HttpResult<T>> {
  const run = createRun(deps);
  return async <T>(req: HttpRequest): Promise<HttpResult<T>> => {
    const log =
      deps.logger !== undefined && deps.logRequests === true
        ? deps.logger.start({ method: req.method, baseUrl: deps.baseUrl, endpoint: req.endpoint, signal: req.signal })
        : undefined;
    if (log === undefined) return run<T>(req);
    let result: HttpResult<T>;
    try {
      result = await run<T>(req);
    } catch (error) {
      log.finish(undefined, error);
      throw error;
    }
    log.finish(result);
    return result;
  };
}

function createRun(deps: HttpDeps): <T>(req: HttpRequest) => Promise<HttpResult<T>> {
  return async <T>(req: HttpRequest): Promise<HttpResult<T>> => {
    const doFetch = deps.fetch ?? globalThis.fetch;
    const url = resolveUrl(deps.baseUrl, req.endpoint);
    const headers: Record<string, string> = { Accept: 'application/json' };
    // A path is joined to baseUrl, so only an absolute endpoint can leave baseUrl's origin.
    const deviceAllowed = !ABSOLUTE_URL.test(req.endpoint) || sameOrigin(deps.baseUrl, url);
    if (req.device === true && deviceAllowed) Object.assign(headers, await deps.deviceHeaders());
    if (req.form !== undefined) headers['Content-Type'] = 'application/x-www-form-urlencoded';
    else if (req.body !== undefined) headers['Content-Type'] = 'application/json';
    if (req.bearer === true) Object.assign(headers, await deps.authHeaders());
    Object.assign(headers, req.headers ?? {});

    const caller = req.signal;
    if (caller?.aborted) throw caller.reason;
    const controller = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, deps.timeoutMs ?? DEFAULT_TIMEOUT_MS);
    const onAbort = (): void => controller.abort(caller?.reason);
    caller?.addEventListener('abort', onAbort, { once: true });

    const module = req.module;
    let response: Response;
    let text: string;
    try {
      const init: RequestInit = { method: req.method, headers, signal: controller.signal };
      if (req.form !== undefined) init.body = new URLSearchParams(req.form).toString();
      else if (req.body !== undefined) init.body = JSON.stringify(req.body);
      if (req.credentials !== undefined) init.credentials = req.credentials;
      try {
        response = await doFetch(url, init);
        if (!response.ok) throw await authErrorFromResponse(response, { module, disabledOn404: req.disabledOn404 });
        text = await response.text();
      } catch (e) {
        if (e instanceof SpAuthError) throw e;
        if (caller?.aborted) throw caller.reason;
        // Only the rejection's `name`: fetch wrappers (e.g. ofetch's FetchError) carry the request options, Authorization included.
        if (timedOut) {
          throw new SpAuthError({ status: 0, code: 'timeout', message: 'Request timed out', module, cause: sanitizedCause(e) });
        }
        throw new SpAuthError({ status: 0, code: 'network', message: 'Network request failed', module, cause: sanitizedCause(e) });
      }
    } finally {
      clearTimeout(timer);
      caller?.removeEventListener('abort', onAbort);
    }
    return { body: parseBody(text) as T, response };
  };
}
