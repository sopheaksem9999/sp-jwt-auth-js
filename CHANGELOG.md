# @sokpheak/sp-jwt-auth

## Unreleased

### Minor Changes

- Added `keyValueTokenStore(storage, keys?)`, a `TokenStore` that keeps each field under its own key in any sync or async `KeyValueStorage` (a superset of `localStorage`, so it drops in; also fits a native keychain wrapper). Key names default to `sp_access_token`, `sp_refresh_token`, `sp_access_token_expires_at`, `sp_csrf`, `sp_device_id`, `sp_last_company_id` and can be overridden via `StorageKeys`. The access token is removed first and written last, so an interrupted write reads as logged out.

### Patch Changes

- `dispose()` now also clears the `subscribe` listeners, so a disposed instance no longer notifies them. A token refresh that leaves the state equal (for example an opaque token) does not notify `subscribe`; use `onEvent({ type: 'refresh' })` for that.
- A HTTP 200 whose body is `{ success: false }` now throws `SpAuthError` with `status` 200, `code` `'request_failed'`, the body `message`, a numeric `errorCode` (from `error_code`) and `requestId` (from `meta.request_id`), for `login`, `verifySecondFactor`, the `/otp` methods, `mfa.resend` and refresh. `SpAuthError` gains `errorCode` (also filled from non-2xx envelope bodies). Callers matching `code === 'unknown'` on login, OTP or refresh failures now see `request_failed`; `mfa.resend` now rejects instead of resolving. A refresh that fails this way keeps the session, except `errorCode` 10002 or 10010, which end it (`refresh_rejected`).
- A token pair now needs only a non-empty `access_token`: a missing, non-numeric or negative `expires_in` is treated as no expiry (numeric strings are parsed) instead of failing the login or refresh. The JWT `exp` still takes precedence.

## 0.2.0

### Minor Changes

- Enhanced session lifecycle and hydration observability:
  - Added strongly-typed `SessionEndReason` (`'manual_logout' | 'cross_tab_logout' | 'token_expired' | 'refresh_rejected' | 'storage_cleared'`) and typed `SessionEndedEvent` payload emitted on `session_ended` events.
  - Added synchronous `isHydrated(): boolean` check on auth instance to distinguish between active initialization and unauthenticated state.
  - Added explicit `ready(): Promise<UserSession | null>` method for awaiting hydration.

## 0.1.1

### Patch Changes

- 898c0ff: Public-repo hygiene release. The second built-in preset is now `presets.spSaas` (a neutral name for the `{ success, data }` envelope host with second factor, company switch and account routes); if you used the previous second preset, switch to `presets.spSaas`, the routes and behaviour are the same. Adds a CI check against client names in a public repo and a gitleaks secret scan before every release. No runtime change otherwise.

## 0.1.0

### Minor Changes

- 30f3fbc: First release (0.1) of the typed JavaScript client for the `sopheak/sp-jwt-auth` Laravel package (backend `^0.1.25`). ESM and CJS, no runtime dependencies; browsers, edge runtimes, Node 20+, Deno and Bun.
  
  - **Core session**: `createJwtAuth({ baseUrl, endpoints?, mode, unwrap?, ... })` with `login` / `verifySecondFactor` (a `LoginResult` of `authenticated` or `second_factor_required`), `logout` (local first, best-effort revoke), `whoami`, `switchCompany`, `getAccessToken` / `getHeaders` with proactive refresh, single-flight refresh, retry-once `handleUnauthorized` (the `ApiAuth` contract of `@sokpheak/sp-laravel-api`), framework-agnostic `getState` / `subscribe`, claims and scope helpers, and one `SpAuthError` type with documented codes.
  - **`userSession`**: body transport (`memoryStore`, `webStorageStore`; the default store is a fresh `memoryStore()` per client) and the httpOnly-cookie transport (`transport: 'cookie'`: refresh token never visible to JavaScript, access token in memory, CSRF double-submit, `restore()` on page load, `readCookie`).
  - **Cross-tab refresh**: Web Locks with an in-process fallback, `BroadcastChannel` with a `storage`-event fallback, adoption of another tab's rotation, `broadcastGraceMs` for the cookie transport. On by default for a `webStorageStore` and, in a real browser tab, for the cookie transport with any store; servers (including Node-like runtimes with a global `document`, such as jsdom) stay store-scoped (no process-wide lock or channel).
  - **Server modes**: `staticToken`, `clientCredentials` (OAuth client credentials, cached and re-fetched before expiry) and `apiKey`.
  - **Presets**: `presets.spJwtTest` and `presets.spSaas`.
  - **Subpath modules**: `/verify` (`createVerifier`, JWKS verification with the optional peer `jose`), `/otp` (first-factor OTP), `/mfa` (second-factor resend), `/oauth` (`oauthAuthorizationCode` with PKCE S256 and state-keyed pending logins, `oauth(auth, creds)` introspect / revoke for servers, `pkceChallenge`), `/sessions` (list and revoke sessions and devices), `/account` (password reset, e-mail verification) and `/social` (redirect URL and callback completion).
  - **Hardening**: errors, events and causes are sanitised in the package code (no response bodies or token values; the `logout` event's `remoteError` is `{ status, code }` only). Recorded contract fixtures will need the scrub helper: review them before committing fixtures.
  
  Caveats: the contract tests against the real backends (`sp-jwt-test`, SaaS) are written but not yet run or recorded, so they stay skipped; the cookie transport has been verified end to end against the fake backend only.
