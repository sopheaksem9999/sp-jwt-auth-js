import { SpAuthError, sanitizedCause } from './errors';

/** How a response body is unwrapped: none, Laravel `{data}`, the sp-laravel-api envelope, or a custom function. */
export type Unwrap = 'raw' | 'laravel' | 'sp-laravel-api' | ((body: unknown) => unknown);

/** Raw token-pair shape returned by the server. */
export interface TokenPairRaw {
  access_token: string;
  refresh_token?: string;
  /** Lifetime in seconds. `findTokenPair` normalises a missing or unusable value to 0 (no expiry). */
  expires_in: number;
  token_type: string;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** Unwraps a response body according to `mode`; bodies without the expected wrapper pass through unchanged. */
export function unwrap(mode: Unwrap, body: unknown): unknown {
  if (typeof mode === 'function') return mode(body);
  if (mode === 'raw') return body;
  if (mode === 'laravel') return isRecord(body) && 'data' in body ? body.data : body;
  // sp-laravel-api: { success, error_code, data, meta }
  return isRecord(body) && 'success' in body && 'data' in body ? body.data : body;
}

/**
 * @internal `unwrap` for the package's own response handling: an error thrown by a
 * function-valued `unwrap` becomes `SpAuthError('unknown')` with a fixed message, no
 * `body`, and a cause reduced to its `name` (the thrown value may carry the response).
 */
export function unwrapOrThrow(mode: Unwrap, body: unknown, module?: string): unknown {
  try {
    return unwrap(mode, body);
  } catch (e) {
    throw new SpAuthError({ status: 0, code: 'unknown', message: 'Response could not be unwrapped', module, cause: sanitizedCause(e) });
  }
}

function lifetime(v: unknown): number {
  const n = typeof v === 'number' ? v : typeof v === 'string' && v.trim() !== '' ? Number(v) : Number.NaN;
  // `0` means "unknown"; missing, non-numeric, NaN, negative and infinite values are not a usable lifetime.
  return Number.isFinite(n) && n > 0 ? n : 0;
}

function asPair(v: unknown): TokenPairRaw | null {
  if (!isRecord(v) || typeof v.access_token !== 'string' || v.access_token === '') return null;
  return { ...v, expires_in: lifetime(v.expires_in) } as unknown as TokenPairRaw;
}

/**
 * Finds a token pair in an unwrapped body: the object itself, then `.token`, then `.data`.
 * A pair needs only a non-empty `access_token`; `expires_in` that is missing or unusable becomes 0 (no expiry).
 */
export function findTokenPair(unwrapped: unknown): TokenPairRaw | null {
  if (!isRecord(unwrapped)) return null;
  return asPair(unwrapped) ?? asPair(unwrapped.token) ?? asPair(unwrapped.data);
}

/** Detects a second-factor challenge on the RAW (not unwrapped) body. */
export function detectChallenge(rawBody: unknown): { kind: '2fa_token' | 'challenge_id'; token: string } | null {
  if (!isRecord(rawBody)) return null;
  const t = rawBody['2fa_token'];
  if (rawBody.requires_2fa === true && typeof t === 'string' && t !== '') return { kind: '2fa_token', token: t };
  const c = rawBody.challenge_id;
  if (typeof c === 'string' && c !== '') return { kind: 'challenge_id', token: c };
  return null;
}
