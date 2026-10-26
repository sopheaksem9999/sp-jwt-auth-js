# @sopheak/sp-jwt-auth

Typed JavaScript client for the [`sopheak/sp-jwt-auth`](https://packagist.org/packages/sopheak/sp-jwt-auth) Laravel package: token storage, refresh and session helpers. ESM and CJS, no runtime dependencies, runs in browsers, edge runtimes and Node 20+. `jose` is an optional peer dependency, needed only by the `verify` module.

> Status: scaffold. Modules below are added one at a time.

## Install

```sh
npm install @sopheak/sp-jwt-auth
# only if you use @sopheak/sp-jwt-auth/verify
npm install jose
```

## Modules

Each module is a function that takes the core auth object. Import only what you use; bundlers drop the rest.

| Backend module | Import path | Client provides |
|---|---|---|
| Core: `JwtTokenService`, guard, `TokenContext`; `token_endpoints`; host login / 2FA; `api_keys` | `@sopheak/sp-jwt-auth` (core) | `createJwtAuth`, state/subscribe, storage stores, refresh rules, `getHeaders`, `handleUnauthorized`, scope checks, claims, rotation, single-flight, cross-tab lock, `login`, `verifySecondFactor`, `logout`, `whoami`, `switchCompany`, `apiKey()` mode |
| `first_factor_otp` | `@sopheak/sp-jwt-auth/otp` | `otp(auth).request / resend / resendByDestination / verify` |
| `mfa` | `@sopheak/sp-jwt-auth/mfa` | `mfa(auth).resend(challenge)` |
| Sessions | `@sopheak/sp-jwt-auth/sessions` | `sessions(auth).list / revoke / revokeOthers / revokeDevice` |
| `oauth_server` | `@sopheak/sp-jwt-auth/oauth` | `clientCredentials` mode, `oauthAuthorizationCode` mode (PKCE S256), `introspect`, `revoke` |
| `external_identities` | `@sopheak/sp-jwt-auth/social` | `social(auth).redirectUrl / completeFromCallback` |
| `password_reset`, `email_verification` | `@sopheak/sp-jwt-auth/account` | `account(auth).forgotPassword / resetPassword / resendVerification / verifyEmail` |
| `keys` / JWKS | `@sopheak/sp-jwt-auth/verify` | `createVerifier` (uses optional peer `jose`) |

## Backend compatibility

| `@sopheak/sp-jwt-auth` | `sopheak/sp-jwt-auth` (Laravel) |
|---|---|
| `0.1` | `^0.1.25` |

## License

MIT. Copyright (c) 2026 Sem Sopheak.
