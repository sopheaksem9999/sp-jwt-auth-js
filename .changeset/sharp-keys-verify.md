---
'@sopheak/sp-jwt-auth': minor
---

Adds `@sopheak/sp-jwt-auth/verify`: `createVerifier({ jwksUrl, issuer, audience?, algorithms?, cooldownMs?, fetch? })` verifies Laravel-issued access tokens against the JWKS (RS256 by default; `jose` is an optional peer imported only from this subpath). Failures throw `SpAuthError` (`invalid_token`, or `network` when the JWKS cannot be loaded); the key set is refreshed every `cacheMaxAgeMs` (10 min), kept for up to `maxStaleMs` (24 h) while the JWKS is unreachable, replaced wholesale by a successful fetch (retired keys dropped), and refetched at most once per `cooldownMs` on an unknown `kid`. Signature and claims only: it cannot see logouts or revocations.
