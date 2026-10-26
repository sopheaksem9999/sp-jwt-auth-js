// The ONLY place in the package that imports `jose` (an optional peer dependency). Keep it that way.
import { createRemoteJWKSet, customFetch, errors, jwtVerify } from 'jose';
import type { JWTVerifyGetKey } from 'jose';
import { decodeClaims } from '../core/claims';
import type { Claims } from '../core/claims';
import { SpAuthError } from '../core/errors';

/** Options for `createVerifier`. */
export interface VerifierOptions {
  /** URL of the JWKS document, e.g. `https://api.example.com/.well-known/sp-jwt-auth/jwks.json`. */
  jwksUrl: string;
  /** Required `iss` claim; a token from any other issuer is rejected. */
  issuer: string;
  /** Required `aud` claim. When omitted the audience is not checked. */
  audience?: string;
  /** Accepted signature algorithms. Default `['RS256']`. Only RSA algorithms are allowed (the JWKS publishes RSA keys only). */
  algorithms?: string[];
  /** Minimum time in ms between two JWKS refetches triggered by an unknown `kid` (jose `cooldownDuration`). Default 30 000. */
  cooldownMs?: number;
  /** `fetch` used to load the JWKS. Default: the global `fetch`. */
  fetch?: typeof fetch;
}

/** Algorithms a verifier may be configured with. HMAC and `none` are never allowed. */
const ALLOWED_ALGORITHMS = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512'];

function invalidToken(message: string, cause?: unknown): SpAuthError {
  return new SpAuthError({ status: 0, code: 'invalid_token', message, module: 'verify', cause });
}

/**
 * Builds a function that verifies a Laravel-issued access token (signature, `iss`, optional `aud`, `exp`, `nbf`) against
 * the backend's JWKS and returns its claims, normalised like `decodeClaims` (`sub` string, `scopes` string array).
 *
 * The key set is cached and refetched on an unknown `kid` (at most once per `cooldownMs`), so key rotation needs no
 * restart. When a refetch fails, the last good key set is kept.
 *
 * Errors, always `SpAuthError` and never containing the token text:
 * - `invalid_token`: anything wrong with the token (empty, malformed, bad signature, wrong `iss`/`aud`, expired, `nbf` in
 *   the future, algorithm not allowed, `kid` not in the key set even after a refetch).
 * - `network` (status 0): the JWKS could not be retrieved or parsed and no usable key was cached. This is not the token's
 *   fault, so callers may answer 503 instead of 401.
 *
 * Limit: this cannot see logouts or revocations (the server checks a database row per `jti`); use `whoami` for
 * revocation-sensitive actions and keep access TTLs short.
 *
 * @throws TypeError when called with an invalid configuration (bad URL, empty issuer, or an algorithm other than RSA ones).
 */
export function createVerifier(o: VerifierOptions): (token: string) => Promise<Claims> {
  const algorithms = o.algorithms ?? ['RS256'];
  if (algorithms.length === 0 || algorithms.some((a) => !ALLOWED_ALGORITHMS.includes(a))) {
    throw new TypeError(`createVerifier: algorithms must be a non-empty subset of ${ALLOWED_ALGORITHMS.join(', ')}`);
  }
  if (typeof o.issuer !== 'string' || o.issuer === '') throw new TypeError('createVerifier: issuer is required');
  const url = new URL(o.jwksUrl); // throws TypeError on an invalid URL
  const jwks = createRemoteJWKSet(url, {
    ...(o.cooldownMs !== undefined ? { cooldownDuration: o.cooldownMs } : {}),
    ...(o.fetch ? { [customFetch]: o.fetch } : {}),
  });

  return async (token: string): Promise<Claims> => {
    if (typeof token !== 'string' || token === '') throw invalidToken('Token is missing or empty.');
    let retrieval: unknown;
    const getKey: JWTVerifyGetKey = async (header, jws) => {
      try {
        return await jwks(header, jws);
      } catch (e) {
        // A missing/ambiguous kid is the token's problem; anything else means the key set could not be loaded.
        if (!(e instanceof errors.JWKSNoMatchingKey || e instanceof errors.JWKSMultipleMatchingKeys)) retrieval = e;
        throw e;
      }
    };
    try {
      await jwtVerify(token, getKey, {
        issuer: o.issuer,
        ...(o.audience !== undefined ? { audience: o.audience } : {}),
        algorithms,
        requiredClaims: ['exp'],
      });
    } catch (e) {
      if (retrieval !== undefined) {
        throw new SpAuthError({ status: 0, code: 'network', message: 'Could not retrieve the JWKS to verify the token.', module: 'verify', cause: retrieval });
      }
      const reason = e instanceof errors.JOSEError ? e.message : 'verification failed';
      throw invalidToken(`Token is not valid: ${reason}.`, e);
    }
    const claims = decodeClaims(token);
    if (claims === null) throw invalidToken('Token payload is not valid.');
    return claims;
  };
}
