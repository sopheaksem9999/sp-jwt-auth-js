# `@sokpheak/sp-jwt-auth/social`

Client for social login. Backend: `external_identities` (config flag `external_identities.enabled`, `config/sp-jwt-auth.php:153-158`; the `ExternalIdentityProvider` contract and `ExternalIdentityStore`, `src/Services/ExternalIdentityStore.php:14`). The package ships **no routes** (hosts use Socialite): they are **host-owned** and configured through `endpoints.socialRedirect` and `endpoints.socialCallback`, each with a `:provider` placeholder. An unset one, or one without the `:provider` placeholder, throws `SpAuthError('not_configured', module 'social')` before any request.

```ts
import { social } from '@sokpheak/sp-jwt-auth/social';

location.href = social(auth).redirectUrl('google');
// on the callback page
await social(auth).completeFromCallback('google', { code, state });
```

- `redirectUrl(provider)`: pure builder, `baseUrl` + `endpoints.socialRedirect` with `:provider` replaced by `encodeURIComponent(provider)`. No network, no state change. An absolute `socialRedirect` stays absolute. Empty, `.` and `..` providers are rejected.
- `completeFromCallback(provider, params)`: `POST endpoints.socialCallback` with the params as the JSON body, unauthenticated, with device headers (when the `device` option is set). The returned pair is stored through the normal session path; cookie transport sends credentials and keeps only the CSRF value. On any failure nothing is stored. Provider is a separate argument (a design choice: it selects the route).

**No OIDC.** The package has no ID tokens, userinfo or discovery; the host exchanges the provider code and answers with this package's token pair.

## Errors (`SpAuthError`, `module: 'social'`)

HTTP failures use the core mapping; a 2xx without a token pair or a throwing `unwrap` is `unknown` with a fixed message (no body; cause reduced via `sanitizedCause`).
