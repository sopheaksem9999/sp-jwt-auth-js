---
'@sopheak/sp-jwt-auth': minor
---

New module `@sopheak/sp-jwt-auth/oauth`: `oauthAuthorizationCode({ clientId, redirectUri, scope, authorizeUrl, tokenUrl?, pendingStore?, clientSecret?, session? })`, a mode whose `beginLogin()` builds the authorize URL (random `state`, PKCE verifier, always `code_challenge_method=S256`, pending record kept in `sessionStorage` or memory) and whose `completeLogin(callbackUrl)` checks `state` (single use), exchanges the code and stores the pair through the normal session path; `oauth(auth, { clientId, clientSecret, auth? })` with `introspect(token)` (RFC 7662 and the legacy camelCase shape mapped to `{ active, clientId, userId, scopes, expiresAt, tokenId }`) and `revoke(token, hint?)`, server-side only; and `pkceChallenge` / `generateCodeVerifier` (Web Crypto).
