import { SpAuthError, sanitizedCause } from '../core/errors';
import type { Challenge, JwtAuth } from '../core/types';

/** The `mfa(auth)` module surface. */
export interface MfaModule {
  /**
   * POSTs the challenge to `endpoints.secondFactorResend` (host route; throws
   * `SpAuthError('not_configured')` with module `mfa` when unset) and returns the
   * response body unwrapped per the `unwrap` option. Body: `{ '2fa_token': token }` or `{ challenge_id: token }`.
   * Verifying the code stays core `auth.verifySecondFactor`.
   */
  resend(challenge: Challenge): Promise<unknown>;
}

const MODULE = 'mfa';

/**
 * MFA module (backend `mfa` OTP challenge brokers; the routes are host code).
 *
 * @param auth The client from `createJwtAuth`.
 */
export function mfa(auth: JwtAuth): MfaModule {
  return {
    async resend(challenge) {
      const endpoint = auth.endpoint('secondFactorResend', MODULE);
      const body = challenge.kind === '2fa_token' ? { '2fa_token': challenge.token } : { challenge_id: challenge.token };
      const { body: raw } = await auth.http<unknown>({
        method: 'POST',
        endpoint,
        body,
        bearer: false,
        module: MODULE,
      });
      try {
        return auth.unwrap(raw);
      } catch (cause) {
        throw new SpAuthError({ status: 0, code: 'unknown', message: 'Response could not be unwrapped', module: MODULE, cause: sanitizedCause(cause) });
      }
    },
  };
}
