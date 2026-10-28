/**
 * One line of the optional request log: one entry per HTTP call made through the client
 * (login, refresh, revoke, whoami, second factor, OTP, MFA, social, `auth.http`).
 *
 * SECURITY: every field is fixed and none can hold a header, a body, a query string, a
 * password, a code or a token. Do NOT add a field that can; that is a leak by design.
 */
export interface AuthLogEntry {
  /** HTTP method as passed to the client (for example `POST`). */
  method: string;
  /** Pathname only: no scheme, host, query or fragment. Logged verbatim, so a path segment (a session id) is part of it. */
  path: string;
  /** HTTP status, or `null` when no response arrived (network failure, timeout, abort). */
  status: number | null;
  /** Milliseconds from the start of the call to its outcome. */
  durationMs: number;
  /** `X-Request-Id` response header, else the body's `meta.request_id`; cleaned and cut to 128 characters. */
  requestId: string | null;
  /** 1-based attempt number. The client makes one HTTP attempt per call, so this is always `1`. */
  attempt: number;
  /** `SpAuthError.code` of a failed call, `'request_failed'` for a 200 `{ success: false }` envelope, `'aborted'` for a caller abort; otherwise `null`. */
  code: string | null;
  /** The numeric `error_code` of a failed response body, when it has one. */
  errorCode: number | null;
}

/** One logged call; `finish` is called once, with the result or the error the call ended with. It must never throw. */
export interface AuthLogCall {
  finish(result: { body: unknown; response: Response } | undefined, error?: unknown): void;
}

/**
 * What core needs from a logger (`createAuthLogger` from `@sokpheak/sp-jwt-auth/logging`).
 * `start` must never throw; it returns `undefined` to skip a call.
 */
export interface AuthRequestLogger {
  start(ctx: { method: string; baseUrl: string; endpoint: string; signal: AbortSignal | undefined }): AuthLogCall | undefined;
}
