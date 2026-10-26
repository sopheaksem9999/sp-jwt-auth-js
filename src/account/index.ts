import { SpAuthError, sanitizedCause } from '../core/errors';
import type { JwtAuth } from '../core/types';

/** Body of `forgotPassword`. */
export interface ForgotPasswordBody {
  email: string;
}

/** Body of `resetPassword`. */
export interface ResetPasswordBody {
  token: string;
  email: string;
  password: string;
  password_confirmation: string;
}

/** The `account(auth)` module surface. Every method returns the response body unwrapped per the client's `unwrap` option. */
export interface AccountModule {
  /** `POST endpoints.forgotPassword` with `{ email }`, unauthenticated. */
  forgotPassword(b: ForgotPasswordBody): Promise<unknown>;
  /**
   * `POST endpoints.resetPassword`, unauthenticated. After a SUCCESSFUL reset the stored
   * session is cleared (the backend does not revoke sessions on reset; hosts should call `revokeAllForUser`).
   */
  resetPassword(b: ResetPasswordBody): Promise<unknown>;
  /** `POST endpoints.resendVerification`, no body; sends the bearer when a token is held, never requires one. */
  resendVerification(): Promise<unknown>;
  /** `POST endpoints.verifyEmail` with `params` (e.g. `id`, `hash`, `expires`, `signature`) as the JSON body, unauthenticated. */
  verifyEmail(params: Record<string, unknown>): Promise<unknown>;
}

const MODULE = 'account';

/**
 * Password reset and e-mail verification (backend `password_reset` and
 * `email_verification` brokers, config `sp-jwt-auth.php:131-141`). The package ships
 * brokers only: the routes are HOST-owned and configured via `endpoints.forgotPassword`,
 * `resetPassword`, `resendVerification` and `verifyEmail`; an unset one throws `not_configured`.
 *
 * @param auth The client from `createJwtAuth`.
 */
export function account(auth: JwtAuth): AccountModule {
  const post = async (name: 'forgotPassword' | 'resetPassword' | 'resendVerification' | 'verifyEmail', body: unknown, bearer: boolean): Promise<unknown> => {
    const endpoint = auth.endpoint(name, MODULE);
    const { body: raw } = await auth.http<unknown>({ method: 'POST', endpoint, ...(body === undefined ? {} : { body }), bearer, module: MODULE });
    try {
      return auth.unwrap(raw);
    } catch (cause) {
      throw new SpAuthError({ status: 0, code: 'unknown', message: 'Response could not be unwrapped', module: MODULE, cause: sanitizedCause(cause) });
    }
  };

  return {
    forgotPassword: (b) => post('forgotPassword', b, false),
    async resetPassword(b) {
      const result = await post('resetPassword', b, false);
      await auth.clearSession();
      return result;
    },
    resendVerification: () => post('resendVerification', undefined, true),
    verifyEmail: (params) => post('verifyEmail', params, false),
  };
}
