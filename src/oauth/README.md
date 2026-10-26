# `@sopheak/sp-jwt-auth/oauth`

Client for the backend's `oauth_server` module (config flag `sp-jwt-auth.oauth_server.*`, **off by default**: the routes answer 404, which this module reports as `SpAuthError('module_disabled')`, module `oauth`). Mirrors `routes/oauth.php` (`/token` :12, `/revoke` :14, `/introspect` :16, under the `oauth_server.route_prefix`) and `OAuthServerService.php` (`validateAuthorizationRequest` :45-82, `revokeToken` :165, `introspect` :184, `issueAuthorizationCodeToken` :244, client credentials :321-336, `validPkce` :413).

## Authorization code + PKCE (`oauthAuthorizationCode`)

For an app that logs users in through your Laravel app's `oauth_server`. The host must serve the authorize page (`/oauth/authorize`: the package gives you `validateAuthorizationRequest` / `approveAuthorizationRequest`, not a route); this mode talks to `/oauth/token`.

```ts
import { createJwtAuth, webStorageStore } from '@sopheak/sp-jwt-auth';
import { oauthAuthorizationCode } from '@sopheak/sp-jwt-auth/oauth';

const oauthMode = oauthAuthorizationCode({
  clientId: 'my-spa',
  redirectUri: 'https://app.example.com/callback',
  scope: 'read write',
  authorizeUrl: 'https://api.example.com/oauth/authorize',
  session: { storage: webStorageStore('localStorage', 'my-app:auth') }, // where the tokens live
});
const auth = createJwtAuth({ baseUrl: 'https://api.example.com/api', endpoints: {}, mode: oauthMode });

location.assign(await oauthMode.beginLogin());   // 1. redirect to the host
await oauthMode.completeLogin(location.href);     // 2. on the callback page
```

The app holds the returned mode object; `beginLogin` / `completeLogin` are bound to the client created with it (before that they reject `not_configured`). **One mode per client**: passing the same mode to a second `createJwtAuth` throws `not_configured` unless the first client was `dispose()`d. Tokens are held by an inner `userSession` (`session` takes its options, including `transport: 'cookie'`), so refresh, storage, cross-tab behaviour and `getState()` are exactly those of a user session.

- `beginLogin()` generates `state` (256 random bits, base64url) and a PKCE verifier (64 characters), stores `{ [state]: { verifier, createdAt } }` in the `pendingStore` (default: `sessionStorage` under `sp-jwt-auth:oauth:pending:<clientId>`, feature-detected and guarded, with a memory copy) and returns `authorizeUrl` plus `response_type=code`, `client_id`, `redirect_uri`, `scope`, `state`, `code_challenge`, `code_challenge_method=S256`. An existing query string on `authorizeUrl` is kept.
- `completeLogin(callbackUrl)` reads `code`, `state` and `error` / `error_description` from the **query string**, compares `state` with the pending record, then POSTs `grant_type=authorization_code`, `code`, `redirect_uri`, `client_id`, `code_verifier` (form-encoded) to `tokenUrl` (default `endpoints.oauthToken`, `/oauth/token`) with the device headers when the `device` option is set (and credentials `include` in cookie transport). The response goes through the same path as a login (`acceptTokens`): body transport stores the pair, cookie transport keeps the refresh token in the httpOnly cookie and stores none.
- **Each pending login is single use.** Logins are keyed by `state`, so two started in one tab do not cancel each other. `completeLogin` consumes exactly the entry for the callback's `state` on every outcome (success, callback error, failed exchange), so replaying a callback URL is rejected (`invalid_state`); two simultaneous completions of one URL exchange the code once. A callback with an unknown `state` consumes nothing (a forged callback cannot cancel a real login). Entries older than 10 minutes are pruned on read (at most 20 are kept). A custom `pendingStore` whose `set` throws would leave the entry replayable: make `set` reliable.
- Nothing is stored on any failure. The code, verifier, state, secret and token values never appear in thrown errors (including `cause`, which is reduced to a name/status/code copy), events or `getState()`. An invalid token pair throws `unknown` with no `body`.
- The callback `error` is surfaced as the `code` only when it is a well-formed RFC 6749 §5.2 value (printable ASCII without `"` and `\`, at most 64 characters); otherwise `invalid_request`, without echoing it.

### On a server

Create **one mode per user or request**, with a `pendingStore` backed by that user's server session (never a store shared between users: the default on a server is a single in-memory slot, so one user's `beginLogin` would be visible to another):

```ts
app.get('/login', async (req, res) => {
  const mode = oauthAuthorizationCode({ clientId, clientSecret, redirectUri, scope, authorizeUrl, pendingStore: sessionPendingStore(req.session) });
  createJwtAuth({ baseUrl, endpoints: {}, mode });
  res.redirect(await mode.beginLogin());
});
```

A module-level mode shared by requests is refused on the second `createJwtAuth`.

### Always S256

The backend defaults an omitted `code_challenge_method` to **`plain`** when a challenge is sent (`OAuthServerService.php:64`), and `plain` makes the challenge equal to the verifier, which defeats PKCE for anyone who sees the authorize URL. So `beginLogin` always sends `code_challenge_method=S256` and has no option for `plain`.

### Client secret: server-side only

`clientSecret` is for a confidential client on a server and is sent as HTTP Basic (`id:secret`, raw bytes, as the backend reads them at `OAuthServerService.php:326-329`). **Never put a client secret in browser code**: anything in a bundle is public. A browser or mobile client is a public client: omit `clientSecret`; PKCE protects the exchange.

### Errors (`SpAuthError`, `module: 'oauth'`)

| Situation | `code` |
|---|---|
| callback carries `error=…` | that value (`access_denied`, …) when well-formed, else `invalid_request`; a well-formed `error_description` becomes the message |
| `state` missing, different, or no pending login (incl. a replay) | `invalid_state` |
| callback without `code` | `invalid_request` |
| token endpoint 400 / 401 | the RFC 6749 `error` (`invalid_grant`, `invalid_client`, `invalid_scope`, `unsupported_grant_type`, `invalid_request`) |
| 404 | `module_disabled` |
| 2xx without a token pair, or a throwing `unwrap` | `unknown` (fixed message, no body) |
| `beginLogin` / `completeLogin` before the mode is given to `createJwtAuth`; the mode given to a second live client | `not_configured` |
| network / timeout | `network` / `timeout` |

## Introspection and revocation (`oauth(auth, creds)`)

```ts
import { oauth } from '@sopheak/sp-jwt-auth/oauth';

const tokens = oauth(auth, { clientId, clientSecret });           // auth?: 'basic' (default) | 'body'
const info = await tokens.introspect(accessToken);                // { active: false } | { active: true, clientId, userId, scopes, expiresAt, tokenId }
await tokens.revoke(refreshToken, 'refresh_token');               // hint optional
```

Both calls authenticate **as an OAuth client** and only see or affect that client's tokens (other clients' tokens introspect as inactive). They are therefore **server-side only**, like `clientCredentials`: never call them from a browser with a secret. `creds` is required; without it they reject `not_configured`. (The secret of a `clientCredentials` mode is deliberately not exposed to this module.)

| Method | Route (`endpoints.oauthIntrospect` / `endpoints.oauthRevoke`) | Result |
|---|---|---|
| `introspect(token)` | `POST /oauth/introspect`, form `token` | `Introspection` |
| `revoke(token, hint?)` | `POST /oauth/revoke`, form `token`, `token_type_hint` | `void` (RFC 7009: an unknown token is still 200) |

`Introspection` maps RFC 7662 (`scope` string to `scopes[]`, `exp` seconds to `expiresAt: Date`, `client_id`, `sub`, `jti`; `expiresAt` is `null` when absent) and also the pre-0.1.25 camelCase body that hosts with `SP_JWT_OAUTH_LEGACY_RESPONSES=true` return (`clientId`, `userId`, `scopes`, `expiresAt` as an ISO string, `tokenId`). An inactive token is just `{ active: false }`. Note that legacy hosts also return framework error bodies instead of RFC 6749 ones; those surface with the generic codes of `SpAuthError`.

The introspection body is read through the client's `unwrap` option (a throwing function becomes `unknown` with a fixed message; the raw body is tried when the unwrapped one has no `active`).

## PKCE helpers

`pkceChallenge(verifier)` is `base64url(SHA-256(verifier))` without padding, via Web Crypto (`crypto.subtle`: HTTPS or localhost in browsers). `generateCodeVerifier(length = 64)` draws 43 to 128 characters of the RFC 7636 unreserved set with `crypto.getRandomValues` and rejection sampling (no modulo bias).
