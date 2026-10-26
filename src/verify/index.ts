// The ONLY place in the package that imports `jose` (an optional peer dependency). Keep it that way.
import { createLocalJWKSet, errors, jwtVerify } from 'jose';
import type { JSONWebKeySet, JWTVerifyGetKey } from 'jose';
import { decodeClaims } from '../core/claims';
import type { Claims } from '../core/claims';
import { SpAuthError, sanitizedCause } from '../core/errors';

/** Options for `createVerifier`. */
export interface VerifierOptions {
  /** URL of the JWKS document, e.g. `https://api.example.com/.well-known/sp-jwt-auth/jwks.json`. */
  jwksUrl: string;
  /** Required `iss` claim; a token from any other issuer is rejected. */
  issuer: string;
  /** Required `aud` claim (any one of the values when an array). When omitted the audience is not checked. */
  audience?: string | string[];
  /** Accepted signature algorithms. Default `['RS256']`. Only RSA algorithms are allowed (the JWKS publishes RSA keys only). */
  algorithms?: string[];
  /** Minimum time in ms between two JWKS fetch attempts (successful or not) that are triggered by an unknown `kid` or by a stale cache. Default 30 000. */
  cooldownMs?: number;
  /** How long a fetched key set is fresh, in ms. After that the next verify refreshes it. Default 600 000 (10 minutes). */
  cacheMaxAgeMs?: number;
  /** How long, from the last successful fetch, a stale key set keeps being used while the JWKS cannot be refreshed, in ms. After that a failure surfaces as `network`. Default 86 400 000 (24 hours). */
  maxStaleMs?: number;
  /** Timeout of one JWKS request, in ms. Default 5000. */
  timeoutMs?: number;
  /** Clock skew tolerated for `exp` and `nbf`, in seconds (jose `clockTolerance`). Default 0. */
  clockToleranceSeconds?: number;
  /** `fetch` used to load the JWKS. Default: the global `fetch`. Redirects are followed. */
  fetch?: typeof fetch;
}

/** Algorithms a verifier may be configured with. HMAC and `none` are never allowed. */
const ALLOWED_ALGORITHMS = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512'];

function invalidToken(message: string, cause?: unknown): SpAuthError {
  return new SpAuthError({ status: 0, code: 'invalid_token', message, module: 'verify', cause: sanitizedCause(cause) });
}

function networkError(message: string, cause?: unknown): SpAuthError {
  return new SpAuthError({ status: 0, code: 'network', message, module: 'verify', cause: sanitizedCause(cause) });
}

function duration(value: number | undefined, fallback: number, name: string): number {
  if (value === undefined) return fallback;
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
    throw new TypeError(`createVerifier: ${name} must be a non-negative number`);
  }
  return value;
}

/**
 * Builds a function that verifies a Laravel-issued access token (signature, `iss`, optional `aud`, `exp`, `nbf`) against
 * the backend's JWKS and returns its claims, normalised like `decodeClaims` (`sub` string, `scopes` string array).
 *
 * Key cache (own implementation over jose `createLocalJWKSet`):
 * - A fetched key set is fresh for `cacheMaxAgeMs` (10 minutes); the next verify after that refreshes it.
 * - If a refresh fails, the last good key set keeps being used for up to `maxStaleMs` (24 hours) after it was fetched;
 *   after that, and when no key set was ever fetched, the failure is `network`.
 * - A token with an unknown `kid` triggers one refetch, at most once per `cooldownMs`; if that refetch fails the last good
 *   set is kept and the token fails as `invalid_token`.
 * - A successful fetch replaces the whole set, so retired keys stop verifying.
 * - Concurrent callers share one in-flight fetch. JWKS redirects are followed (`fetch` default).
 *
 * Errors, always `SpAuthError` and never containing the token text:
 * - `invalid_token`: anything wrong with the token (empty, malformed, bad signature, wrong `iss`/`aud`, expired, `nbf` in
 *   the future, algorithm not allowed, `kid` not in the key set even after a refetch).
 * - `network` (status 0): the JWKS could not be retrieved or parsed and no usable key set was available. This is not the
 *   token's fault, so callers may answer 503 instead of 401.
 *
 * Limit: this cannot see logouts or revocations (the server checks a database row per `jti`); use `whoami` for
 * revocation-sensitive actions and keep access TTLs short.
 *
 * @throws TypeError when called with an invalid configuration (bad URL, empty issuer, negative durations, or an algorithm other than RSA ones).
 */
export function createVerifier(o: VerifierOptions): (token: string) => Promise<Claims> {
  const algorithms = o.algorithms ?? ['RS256'];
  if (algorithms.length === 0 || algorithms.some((a) => !ALLOWED_ALGORITHMS.includes(a))) {
    throw new TypeError(`createVerifier: algorithms must be a non-empty subset of ${ALLOWED_ALGORITHMS.join(', ')}`);
  }
  if (typeof o.issuer !== 'string' || o.issuer === '') throw new TypeError('createVerifier: issuer is required');
  const url = new URL(o.jwksUrl).href; // throws TypeError on an invalid URL
  const cooldownMs = duration(o.cooldownMs, 30_000, 'cooldownMs');
  const cacheMaxAgeMs = duration(o.cacheMaxAgeMs, 600_000, 'cacheMaxAgeMs');
  const maxStaleMs = duration(o.maxStaleMs, 86_400_000, 'maxStaleMs');
  const timeoutMs = duration(o.timeoutMs, 5000, 'timeoutMs');
  const clockTolerance = duration(o.clockToleranceSeconds, 0, 'clockToleranceSeconds');
  const doFetch: typeof fetch = o.fetch ?? ((input, init) => globalThis.fetch(input, init));

  let local: ReturnType<typeof createLocalJWKSet> | undefined;
  let fetchedAt = 0;
  let lastAttemptAt = Number.NEGATIVE_INFINITY;
  let lastError: unknown;
  let pending: Promise<void> | undefined;

  async function load(): Promise<void> {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), timeoutMs);
    try {
      const res = await doFetch(url, { method: 'GET', signal: ctl.signal, headers: { accept: 'application/json' } });
      if (res.status !== 200) throw networkError(`JWKS request failed with HTTP ${res.status}.`);
      const json = (await res.json()) as unknown;
      if (typeof json !== 'object' || json === null || !Array.isArray((json as { keys?: unknown }).keys)) {
        throw networkError('JWKS response is not a key set.');
      }
      const set = createLocalJWKSet(json as JSONWebKeySet); // throws on a malformed set; the old set is kept
      local = set;
      fetchedAt = Date.now();
      lastError = undefined;
    } catch (e) {
      lastError = e instanceof SpAuthError ? e : networkError('Could not retrieve the JWKS.', e);
      throw lastError;
    } finally {
      clearTimeout(timer);
    }
  }

  /** One shared in-flight fetch; every caller awaits the same promise, so a rejection is always observed. */
  function refresh(): Promise<void> {
    if (!pending) {
      lastAttemptAt = Date.now();
      const p: Promise<void> = load().finally(() => {
        if (pending === p) pending = undefined;
      });
      pending = p;
    }
    return pending;
  }

  const getKey: JWTVerifyGetKey = async (header, jws) => {
    if (!local) {
      await refresh(); // nothing cached: a failure is `network` right away
    } else if (Date.now() - fetchedAt >= cacheMaxAgeMs) {
      let failure: unknown;
      if (pending || Date.now() - lastAttemptAt >= cooldownMs) {
        try {
          await refresh();
        } catch (e) {
          failure = e;
        }
      } else {
        failure = lastError;
      }
      if (failure !== undefined && Date.now() - fetchedAt >= maxStaleMs) {
        throw failure instanceof SpAuthError ? failure : networkError('The cached JWKS is too old and could not be refreshed.', failure);
      }
    }
    const current = local as ReturnType<typeof createLocalJWKSet>;
    try {
      return await current(header, jws);
    } catch (e) {
      if (e instanceof errors.JWKSNoMatchingKey && (pending || Date.now() - lastAttemptAt >= cooldownMs)) {
        try {
          await refresh();
        } catch {
          throw e; // refetch failed: keep the last good set; the token's kid is simply unknown
        }
        return (local as ReturnType<typeof createLocalJWKSet>)(header, jws);
      }
      throw e;
    }
  };

  return async (token: string): Promise<Claims> => {
    if (typeof token !== 'string' || token === '') throw invalidToken('Token is missing or empty.');
    try {
      await jwtVerify(token, getKey, {
        issuer: o.issuer,
        ...(o.audience !== undefined ? { audience: o.audience } : {}),
        algorithms,
        requiredClaims: ['exp'],
        clockTolerance,
      });
    } catch (e) {
      if (e instanceof SpAuthError) throw e; // JWKS retrieval failure from getKey
      const reason = e instanceof errors.JOSEError ? e.message : 'verification failed';
      throw invalidToken(`Token is not valid: ${reason}.`, e);
    }
    const claims = decodeClaims(token);
    if (claims === null) throw invalidToken('Token payload is not valid.');
    return claims;
  };
}
