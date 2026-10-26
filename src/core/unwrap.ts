/** How a response body is unwrapped: none, Laravel `{data}`, the sp-laravel-api envelope, or a custom function. */
export type Unwrap = 'raw' | 'laravel' | 'sp-laravel-api' | ((body: unknown) => unknown);

/** Raw token-pair shape returned by the server. */
export interface TokenPairRaw {
  access_token: string;
  refresh_token?: string;
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

function asPair(v: unknown): TokenPairRaw | null {
  if (!isRecord(v) || typeof v.access_token !== 'string' || typeof v.expires_in !== 'number') return null;
  return v as unknown as TokenPairRaw;
}

/** Finds a token pair in an unwrapped body: the object itself, then `.token`, then `.data`. */
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
