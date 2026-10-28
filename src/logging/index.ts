import { SpAuthError } from '../core/errors';
import type { AuthLogEntry, AuthRequestLogger } from '../core/log-types';

export type { AuthLogCall, AuthLogEntry, AuthRequestLogger } from '../core/log-types';

/** Options of `createAuthLogger`. */
export interface AuthLoggerOptions {
  /** Receives one `AuthLogEntry` per HTTP call, called inline: keep it quick. A throw or a rejected promise is ignored. */
  sink: (entry: AuthLogEntry) => unknown;
}

/**
 * Strips C0, DEL, C1 and U+2028/U+2029, cuts to `max` code points (never inside a surrogate pair) and trims; `null`
 * when nothing is left. Same rule as sp-jwt-auth-dart and sp-laravel-api.
 */
function clean(v: unknown, max: number): string | null {
  if (typeof v !== 'string') return null;
  return Array.from(v.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g, '')).slice(0, max).join('').trim() || null;
}

type Rec = Record<string, unknown>;
const rec = (v: unknown): Rec | null => (typeof v === 'object' && v !== null ? (v as Rec) : null);

function numericCode(v: unknown): number | null {
  const n = typeof v === 'string' && /^-?\d{1,15}$/.test(v) ? Number(v) : v;
  return typeof n === 'number' && Number.isSafeInteger(n) ? n : null;
}

function pathOf(baseUrl: string, endpoint: string): string {
  const abs = /^https?:\/\//i.test(endpoint);
  const joined = abs ? endpoint : `${baseUrl.replace(/\/+$/, '')}${endpoint.startsWith('/') ? '' : '/'}${endpoint}`;
  return clean(joined.replace(/^[a-z][a-z0-9+.-]*:\/\/[^/?#]*/i, '').split(/[?#]/)[0], 512) ?? '/';
}

function build(
  method: string,
  path: string,
  startedAt: number,
  aborted: boolean,
  result: { body: unknown; response: Response } | undefined,
  error: unknown,
): AuthLogEntry {
  let status: number | null = null;
  let requestId: string | null = null;
  let code: string | null = null;
  let errorCode: number | null = null;
  if (result) {
    const body = rec(result.body);
    status = result.response.status;
    requestId = clean(result.response.headers.get('X-Request-Id'), 128) ?? clean(rec(body?.meta)?.request_id, 128);
    // A 200 `{ success: false }` envelope is a failure for logging; the call itself is unchanged here.
    if (body?.success === false) {
      code = 'request_failed';
      errorCode = numericCode(body.error_code);
    }
  } else if (error instanceof SpAuthError) {
    status = error.status || null;
    // `code` can be the server's `error` text: only identifier-like values pass.
    code = /^[a-z0-9_.-]{1,64}$/i.test(error.code) ? error.code : 'unknown';
    requestId = clean(error.requestId, 128);
    errorCode = numericCode(rec(error.body)?.error_code);
  } else {
    code = aborted ? 'aborted' : 'unknown';
  }
  return { method, path, status, durationMs: Math.max(0, Date.now() - startedAt), requestId, attempt: 1, code, errorCode };
}

/**
 * Creates the request logger to pass as `createJwtAuth({ logger })` (with `logRequests: true`).
 * Entries carry fixed fields only. The sink is called inline; a synchronous throw, a rejected
 * returned promise and a throwing thenable are all swallowed, so a logged call's result or error is never affected.
 */
export function createAuthLogger(options: AuthLoggerOptions): AuthRequestLogger {
  return {
    start(ctx) {
      try {
        const method = ctx.method;
        const path = pathOf(ctx.baseUrl, ctx.endpoint);
        const startedAt = Date.now();
        return {
          finish(result, error) {
            try {
              // `Promise.resolve(thenable)` calls `then` in a microtask, so a throwing thenable rejects the wrapper and is caught below.
              Promise.resolve(options.sink(build(method, path, startedAt, ctx.signal?.aborted === true, result, error))).catch(() => {});
            } catch {
              /* building the entry or the caller's sink must never change the request result */
            }
          },
        };
      } catch {
        return undefined;
      }
    },
  };
}
