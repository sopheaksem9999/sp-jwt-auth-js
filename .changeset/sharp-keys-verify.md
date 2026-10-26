---
'@sopheak/sp-jwt-auth': minor
---

Adds `@sopheak/sp-jwt-auth/verify`: `createVerifier({ jwksUrl, issuer, audience?, algorithms?, cooldownMs?, fetch? })` verifies Laravel-issued access tokens against the JWKS (RS256 by default; `jose` is an optional peer imported only from this subpath). Failures throw `SpAuthError` (`invalid_token`, or `network` when the JWKS cannot be loaded); key rotation is picked up on an unknown `kid` and a failed refetch keeps the last good key set. Signature and claims only: it cannot see logouts or revocations.
