import { SpAuthError, isSpAuthError } from '../core/errors';
import { resolveUrl } from '../core/http';
import type { JwtAuth } from '../core/types';

/** The `social(auth)` module surface. */
export interface SocialModule {
  /**
   * Pure URL builder, no network and no state change: `baseUrl` joined to
   * `endpoints.socialRedirect` with `:provider` replaced by the URL-encoded provider.
   * Navigate the browser to it. An absolute `socialRedirect` stays absolute.
   */
  redirectUrl(provider: string): string;
  /**
   * `POST endpoints.socialCallback` (`:provider` replaced, URL-encoded) with the callback
   * `params` (e.g. `code`, `state`) as JSON, unauthenticated, with device headers, and stores
   * the returned token pair through the normal session path (cookie transport: only the CSRF
   * value is kept). Resolves with nothing; on any failure nothing is stored.
   */
  completeFromCallback(provider: string, params: Record<string, string>): Promise<void>;
}

const MODULE = 'social';

function fill(endpoint: string, provider: unknown): string {
  if (typeof provider !== 'string' || provider === '' || provider === '.' || provider === '..') {
    throw new SpAuthError({ status: 0, code: 'invalid_request', message: 'Invalid provider', module: MODULE });
  }
  return endpoint.replace(':provider', () => encodeURIComponent(provider));
}

/**
 * Social login (backend `external_identities`: `ExternalIdentityProvider` contract and
 * `ExternalIdentityStore`, config `sp-jwt-auth.php:153-158`, `src/Services/ExternalIdentityStore.php:14`).
 * The package has no routes (hosts use Socialite): they are HOST-owned and configured via
 * `endpoints.socialRedirect` and `endpoints.socialCallback`. There is no OIDC here: no ID tokens, userinfo or discovery.
 *
 * @param auth The client from `createJwtAuth`.
 */
export function social(auth: JwtAuth): SocialModule {
  return {
    redirectUrl(provider) {
      return resolveUrl(auth.baseUrl, fill(auth.endpoint('socialRedirect', MODULE), provider));
    },
    async completeFromCallback(provider, params) {
      const endpoint = fill(auth.endpoint('socialCallback', MODULE), provider);
      const { body, response } = await auth.http<unknown>({
        method: 'POST',
        endpoint,
        body: params,
        bearer: false,
        device: true,
        credentials: auth.credentials,
        module: MODULE,
      });
      try {
        await auth.acceptTokens(body, response);
      } catch (e) {
        if (isSpAuthError(e) && e.module === null) e.module = MODULE; // core errors carry no module; name this one
        throw e;
      }
    },
  };
}
