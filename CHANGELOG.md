# @sopheak/sp-jwt-auth

## 0.1.0

### Minor Changes

- 30f3fbc: First release (0.1) of the typed JavaScript client for the `sopheak/sp-jwt-auth` Laravel package (backend `^0.1.25`). ESM and CJS, no runtime dependencies; browsers, edge runtimes, Node 20+, Deno and Bun.
  
  - **Core session**: `createJwtAuth({ baseUrl, endpoints?, mode, unwrap?, ... })` with `login` / `verifySecondFactor` (a `LoginResult` of `authenticated` or `second_factor_required`), `logout` (local first, best-effort revoke), `whoami`, `switchCompany`, `getAccessToken` / `getHeaders` with proactive refresh, single-flight refresh, retry-once `handleUnauthorized` (the `ApiAuth` contract of `@sopheak/sp-laravel-api`), framework-agnostic `getState` / `subscribe`, claims and scope helpers, and one `SpAuthError` type with documented codes.
  - **`userSession`**: body transport (`memoryStore`, `webStorageStore`; the default store is a fresh `memoryStore()` per client) and the httpOnly-cookie transport (`transport: 'cookie'`: refresh token never visible to JavaScript, access token in memory, CSRF double-submit, `restore()` on page load, `readCookie`).
  - **Cross-tab refresh**: Web Locks with an in-process fallback, `BroadcastChannel` with a `storage`-event fallback, adoption of another tab's rotation, `broadcastGraceMs` for the cookie transport. On by default for a `webStorageStore` and, in a real browser tab, for the cookie transport with any store; servers (including Node-like runtimes with a global `document`, such as jsdom) stay store-scoped (no process-wide lock or channel).
  - **Server modes**: `staticToken`, `clientCredentials` (OAuth client credentials, cached and re-fetched before expiry) and `apiKey`.
  - **Presets**: `presets.spJwtTest` and `presets.speedxSaas`.
  - **Subpath modules**: `/verify` (`createVerifier`, JWKS verification with the optional peer `jose`), `/otp` (first-factor OTP), `/mfa` (second-factor resend), `/oauth` (`oauthAuthorizationCode` with PKCE S256 and state-keyed pending logins, `oauth(auth, creds)` introspect / revoke for servers, `pkceChallenge`), `/sessions` (list and revoke sessions and devices), `/account` (password reset, e-mail verification) and `/social` (redirect URL and callback completion).
  - **Hardening**: errors, events and causes are sanitised in the package code (no response bodies or token values; the `logout` event's `remoteError` is `{ status, code }` only). Recorded contract fixtures will need the scrub helper: review them before committing fixtures.
  
  Caveats: the contract tests against the real backends (`sp-jwt-test`, SaaS) are written but not yet run or recorded, so they stay skipped; the cookie transport has been verified end to end against the fake backend only.
