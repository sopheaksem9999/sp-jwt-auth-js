/**
 * Machine-readable category of a failed auth call; `(string & {})` carries RFC 6749
 * codes such as `invalid_client`. A required second factor is not an error: it is
 * the `LoginResult` status `second_factor_required`.
 */
export type SpAuthErrorCode =
  | 'session_ended'
  | 'invalid_code'
  | 'rate_limited'
  | 'delivery_failed'
  | 'not_configured'
  | 'module_disabled'
  | 'csrf_failed'
  | 'invalid_token'
  | 'invalid_state'
  | 'invalid_request'
  | 'request_failed'
  | 'network'
  | 'timeout'
  | 'unknown'
  | (string & {});

/** Extra context the calling module supplies when converting a response. */
export interface AuthErrorContext {
  /** Name of the module that issued the request. */
  module?: string;
  /** When true, a 404 means the module/feature is disabled rather than a missing record. */
  disabledOn404?: boolean;
}

/** Already-normalised fields accepted by the `SpAuthError` constructor. */
export interface SpAuthErrorInit {
  status: number;
  code: SpAuthErrorCode;
  message: string;
  module?: string | null;
  fieldErrors?: Record<string, string[]>;
  requestId?: string | null;
  retryAfter?: number | null;
  errorCode?: number | null;
  body?: unknown;
  response?: Response | null;
  cause?: unknown;
}

/** Single error shape for every failed auth call (HTTP, envelope, plain Laravel, RFC 6749, HTML, empty, transport). */
export class SpAuthError extends Error {
  status: number;
  code: SpAuthErrorCode;
  module: string | null;
  fieldErrors: Record<string, string[]>;
  requestId: string | null;
  retryAfter: number | null;
  /** Numeric `error_code` of an envelope body (numeric strings accepted), else `null`. */
  readonly errorCode: number | null;
  body: unknown;
  response: Response | null;
  /** Underlying error for transport failures (declared here because the ES2020 lib lacks `Error.cause`). */
  cause?: unknown;

  /** Creates an error from normalised fields; prefer `authErrorFromResponse`. */
  constructor(init: SpAuthErrorInit) {
    super(init.message);
    if (init.cause !== undefined) this.cause = init.cause;
    this.name = 'SpAuthError';
    this.status = init.status;
    this.code = init.code;
    this.module = init.module ?? null;
    this.fieldErrors = init.fieldErrors ?? {};
    this.requestId = init.requestId ?? null;
    this.retryAfter = init.retryAfter ?? null;
    this.errorCode = init.errorCode ?? null;
    this.body = init.body ?? null;
    this.response = init.response ?? null;
  }
}

/**
 * A copy of an underlying error that is safe to attach as `cause`: it keeps the
 * error's `name` (and, for an `SpAuthError`, `status` and `code`) and nothing
 * else. Response bodies, `response`, messages and custom properties (a
 * parser's or `jose`'s payload, a thrown host value) are dropped, because
 * loggers print `cause` recursively and those can hold tokens, codes or secrets.
 * Never attach a raw error from reading a response as `cause`.
 */
export function sanitizedCause(e: unknown): Error | undefined {
  if (e === undefined || e === null) return undefined;
  if (e instanceof SpAuthError) {
    return new SpAuthError({ status: e.status, code: e.code, message: 'Underlying error details omitted', module: e.module });
  }
  const copy = new Error('Underlying error details omitted');
  copy.name = e instanceof Error && typeof e.name === 'string' ? e.name : 'Error';
  return copy;
}

/** Type guard for `SpAuthError`. */
export function isSpAuthError(e: unknown): e is SpAuthError {
  return e instanceof SpAuthError;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** @internal A finite integer, or a numeric string of one, else `null`. */
export function errorCodeFrom(v: unknown): number | null {
  if (typeof v === 'number') return Number.isInteger(v) ? v : null;
  if (typeof v === 'string' && /^-?\d+$/.test(v.trim())) return Number(v.trim());
  return null;
}

function nonEmpty(v: unknown): string {
  return typeof v === 'string' ? v : '';
}

function codeFromStatus(status: number, ctx: AuthErrorContext): SpAuthErrorCode {
  if (status === 422) return 'invalid_code';
  if (status === 429) return 'rate_limited';
  if (status === 502) return 'delivery_failed';
  if (status === 404 && ctx.disabledOn404 === true) return 'module_disabled';
  return 'unknown';
}

function normaliseFieldErrors(raw: unknown): Record<string, string[]> {
  if (!isRecord(raw)) return {};
  const out: Record<string, string[]> = {};
  for (const [key, value] of Object.entries(raw)) {
    if (Array.isArray(value)) out[key] = value.map(String);
    else if (typeof value === 'string') out[key] = [value];
  }
  return out;
}

function parseRetryAfter(header: string | null): number | null {
  if (header === null || header.trim() === '') return null;
  const secs = Number(header);
  if (Number.isFinite(secs)) return secs >= 0 ? secs : null;
  const when = Date.parse(header);
  if (Number.isNaN(when)) return null;
  return Math.max(0, Math.ceil((when - Date.now()) / 1000));
}

/** Converts a non-2xx `Response` into an `SpAuthError`, consuming its body; never throws. */
export async function authErrorFromResponse(res: Response, ctx: AuthErrorContext = {}): Promise<SpAuthError> {
  let text = '';
  try {
    text = await res.text();
  } catch {
    text = '';
  }
  let body: unknown = text === '' ? null : text;
  if (text !== '') {
    try {
      body = JSON.parse(text);
    } catch {
      body = text;
    }
  }

  const obj = isRecord(body) ? body : null;
  const fieldErrors = normaliseFieldErrors(obj?.errors);

  const rfcCode = nonEmpty(obj?.error);
  const code: SpAuthErrorCode = rfcCode !== '' ? rfcCode : codeFromStatus(res.status, ctx);

  let message = nonEmpty(obj?.error_description);
  if (message === '') message = nonEmpty(obj?.message);
  if (message === '') message = fieldErrors.message?.[0] ?? '';
  if (message === '') message = `Request failed with status ${res.status}`;

  const meta = obj !== null && isRecord(obj.meta) ? obj.meta : null;
  const metaId = nonEmpty(meta?.request_id);
  const requestId = metaId !== '' ? metaId : res.headers.get('X-Request-ID');

  const retryAfter = res.status === 429 ? parseRetryAfter(res.headers.get('Retry-After')) : null;

  return new SpAuthError({
    status: res.status,
    code,
    message,
    module: ctx.module ?? null,
    fieldErrors,
    requestId,
    retryAfter,
    errorCode: errorCodeFrom(obj?.error_code),
    body,
    response: res,
  });
}
