# verify

Verifies Laravel-issued access tokens in Node (Express, NestJS, any API) against the backend's JWKS. Import path: `@sokpheak/sp-jwt-auth/verify`.

- **Backend module:** `keys` (JWKS). Route `GET /.well-known/sp-jwt-auth/jwks.json`, on by default; switch off with config `keys.jwks_enabled` (env `SP_JWT_JWKS_ENABLED`).
- **Mirrors:** `src/Signing/JwksFormatter.php:34-45` in `sopheak/sp-jwt-auth` (RSA keys only, each published as `{kty:"RSA",use:"sig",kid,alg,n,e}`; the `RuntimeException` for a non-RSA key is at `:34-36`).
- **Peer dependency:** `jose ^6` (optional). It is imported only from this subpath, so apps that never verify tokens never load it. `dist/index.*` contains no `jose` reference (checked by `scripts/check-dist.mjs`).

```ts
import { createVerifier } from '@sokpheak/sp-jwt-auth/verify';

const verify = createVerifier({ jwksUrl, issuer, audience /* optional */, algorithms: ['RS256'] /* default */ });
const claims = await verify(token); // { sub: string, scopes: string[], exp, sid?, company_id?, ... }
```

Options: `jwksUrl`, `issuer` (required `iss`), `audience` (string or array, checked only when set), `algorithms` (default `['RS256']`), `cooldownMs` (default 30 000), `cacheMaxAgeMs` (default 10 minutes), `maxStaleMs` (default 24 hours), `timeoutMs` (default 5000), `clockToleranceSeconds` (default 0; tolerated skew for `exp`/`nbf`), `fetch` (for the JWKS request; redirects are followed).

## Errors

Every failure is an `SpAuthError`, and the token text is never put in a message.

| `code` | When |
|---|---|
| `invalid_token` | Empty or malformed token, bad signature, wrong `iss` or `aud`, expired, `nbf` in the future, `exp` missing, algorithm not allowed (including `alg: none` and HS256), `kid` not in the key set even after a refetch. |
| `network` (status 0) | The JWKS could not be retrieved or parsed and no usable key was cached. This is not the token's fault: answer 503 rather than 401 if you want to tell them apart. |

`createVerifier` throws a `TypeError` at creation for a bad configuration: an invalid `jwksUrl`, an empty `issuer`, or any algorithm other than RS256/RS384/RS512/PS256/PS384/PS512 (HMAC and `none` are refused up front; the JWKS only publishes RSA keys).

## Key cache and rotation

The verifier keeps its own key cache over jose's `createLocalJWKSet`:

- The fetched key set is fresh for `cacheMaxAgeMs`; the next verify after that refreshes it.
- If the refresh fails (JWKS outage), the last good key set keeps being used for up to `maxStaleMs` after it was fetched. After that, failures surface as `network`. With no key set ever fetched, a failure is `network` immediately.
- A token with an unknown `kid` triggers one refetch, at most once per `cooldownMs`, so rotations need no restart. If that refetch fails the last good set is kept and the token fails as `invalid_token`.
- A successful fetch **replaces** the whole set, so retired (or compromised, see backend J14) keys stop verifying at the next refresh. Stale keys are only trusted during an outage, for at most `maxStaleMs`.
- Concurrent callers share one in-flight fetch.

## Revocation limit

This checks **signature and claims only**. It cannot see logouts or revocations, because the Laravel server checks a database row per `jti` on every request. A revoked token still verifies here until it expires.

- Keep access-token TTLs short (the default is 15 minutes).
- For revocation-sensitive actions (changing a password, payments, admin operations) call the host's `whoami` with the token instead.
