# @sopheak/sp-jwt-auth

Typed JavaScript client for the [`sopheak/sp-jwt-auth`](https://packagist.org/packages/sopheak/sp-jwt-auth) Laravel package: token storage, refresh and session helpers. ESM and CJS, no runtime dependencies, runs in browsers, edge runtimes and Node 20+. `jose` is an optional peer dependency, needed only by the `verify` module (coming in a later release).

> Status: **0.1, core only.** The core session (`createJwtAuth` with `userSession`, body or [httpOnly-cookie](#cookie-transport-httponly-refresh-cookie) transport) and the [server modes](#server-modes) (`staticToken`, `clientCredentials`, `apiKey`) are what this release ships. Everything marked "coming later" below is **not available yet**; do not build on it.

## Install

```sh
npm install @sopheak/sp-jwt-auth
```

## Quick start

Browser or single-user app: tokens persisted in `localStorage`, refreshed for you. This code is run by the test suite (`test/docs/readme-snippets.test.ts`) against a fake `fetch`.

<!-- snippet:quickstart -->
```ts
// import { createJwtAuth, presets, userSession, webStorageStore } from '@sopheak/sp-jwt-auth';

const auth = createJwtAuth({
  baseUrl: 'https://api.example.com', // origin + the host's prefix (e.g. '/api/v2')
  ...presets.spJwtTest, // the host's endpoints and response shape; see "Presets"
  mode: userSession({ storage: webStorageStore('localStorage', 'app_auth') }),
});

const result = await auth.login({ email: 'ada@example.com', password: 'correct horse' });
if (result.status === 'second_factor_required') {
  // hosts with a second factor also set endpoints.secondFactor
  await auth.verifySecondFactor(result.challenge, '123456');
}

console.log(auth.getState().status); // 'authenticated'
console.log(await auth.getHeaders()); // { Authorization: 'Bearer ...' }, refreshed first when due

await auth.logout();
console.log(await auth.getHeaders()); // {}

auth.dispose?.(); // when the client is discarded (an app unmount, a test)
```

`getHeaders()` and `handleUnauthorized()` are the `ApiAuth` contract that `@sopheak/sp-laravel-api` expects, so the client can be passed as its `auth` option without any adapter.

`login()` resolves `{ status: 'authenticated' }` or `{ status: 'second_factor_required', challenge }`. Any failure rejects with an [`SpAuthError`](#error-codes).

## Using it from a framework

`getState()` returns a stable snapshot (same object until something changes) and `subscribe(listener)` returns an unsubscribe function. That is all a framework needs:

| Framework | Primitive | Snippet |
|---|---|---|
| Vue | `shallowRef` | `auth.subscribe(() => (state.value = auth.getState()))` |
| React / Next.js / Remix client components | `useSyncExternalStore` | `useSyncExternalStore(auth.subscribe, auth.getState, auth.getState)` |
| Angular | `signal` | `auth.subscribe(() => state.set(auth.getState()))` |
| Svelte 4 (and `$authState` in Svelte 5) | `readable` | `readable(auth.getState(), (set) => auth.subscribe(() => set(auth.getState())))` |
| Solid | `from` | `from((set) => auth.subscribe(() => set(auth.getState())))` |

The same snippets in context (also executed by the test suite, with stand-ins for each framework primitive):

<!-- snippet:vue -->
```ts
// import { shallowRef } from 'vue';
const state = shallowRef(auth.getState());
auth.subscribe(() => (state.value = auth.getState()));
```

<!-- snippet:react -->
```ts
// import { useSyncExternalStore } from 'react';
const state = useSyncExternalStore(auth.subscribe, auth.getState, auth.getState);
```

<!-- snippet:angular -->
```ts
// import { signal } from '@angular/core';
const state = signal(auth.getState());
auth.subscribe(() => state.set(auth.getState()));
// provide it once: { provide: SP_AUTH, useValue: auth }
```

<!-- snippet:svelte -->
```ts
// import { readable } from 'svelte/store';
const authState = readable(auth.getState(), (set) => auth.subscribe(() => set(auth.getState())));
```

<!-- snippet:solid -->
```ts
// import { from } from 'solid-js';
const state = from((set) => auth.subscribe(() => set(auth.getState())));
```

**Angular and `fetch`.** The client calls `fetch`, not Angular's `HttpClient`, so `HttpClient` interceptors do not see these requests. Put logging or loading state in a wrapper passed as the `fetch` option (a function that calls the real `fetch` and adds the concern). Tests mock through the same `fetch` option. Zone.js tracks `fetch`, so change detection and SSR stability work unchanged.

## Cookie transport (httpOnly refresh cookie)

With the default body transport the 60-day refresh token sits in `localStorage`, where any XSS can read it. With `transport: 'cookie'` JavaScript never sees it: the backend keeps it in an httpOnly cookie. Available now; needs `sopheak/sp-jwt-auth` **0.1.25+** with `SP_JWT_REFRESH_TRANSPORT=cookie` (`both` during a migration) and host login routes wrapped with `TokenResponse::withRefreshCookie()`.

<!-- snippet:cookie -->
```ts
// import { createJwtAuth, userSession, webStorageStore } from '@sopheak/sp-jwt-auth';

const auth = createJwtAuth({
  baseUrl: 'https://api.example.com',
  // refresh and revoke stay on the package routes, under the cookie's path (/auth/token)
  endpoints: { login: '/auth/login' },
  mode: userSession({
    transport: 'cookie',
    storage: webStorageStore('localStorage', 'app_auth'), // only csrf, deviceId, lastCompanyId
  }),
});

await auth.restore(); // page load: one refresh through the cookie; no session -> 'anonymous'
console.log(auth.getState().status); // 'anonymous'

await auth.login({ email: 'ada@example.com', password: 'correct horse' });
console.log(auth.getState().status); // 'authenticated'
console.log(await auth.getHeaders()); // { Authorization: 'Bearer ...' }, from memory

await auth.logout(); // revokes with the bearer AND the cookie (+ X-SP-CSRF)
auth.dispose?.();
```

- **Where things live.** Refresh token: the httpOnly cookie `sp_refresh_token` (path `/auth/token`); the client never reads, stores or sends it, and drops a body `refresh_token` (`both` mode) unread. Access token: memory only. `storage` keeps only non-secret state (`csrf`, `deviceId`, `lastCompanyId`); use `webStorageStore('localStorage', …)` so new tabs and reloads have the CSRF value (`sessionStorage` would leave new tabs without it).
- **Requests.** Login, second factor, refresh, logout, whoami and company switch send `credentials: 'include'`. Refresh sends no body. `switchCompany` sends `{ company_id }` only.
- **Routes.** The cookie is scoped to `/{route_prefix}/token`, so keep `endpoints.refresh` (default `/auth/token/refresh`) and the revoke route (`/auth/token/revoke`, the default when `endpoints.logout` is unset) under that path. A host refresh route elsewhere (such as the presets' `/auth/refresh`) never receives the cookie. The same holds for company switching: the SaaS `/auth/impersonate_in` route (`switchCompany`) lies outside `/auth/token`, so the host must make the refresh cookie available there (cookie path) or keep the body transport for company switching.
- **Page load: call `auth.restore()`.** The state stays `unknown` until it resolves. It calls refresh once: success is `authenticated`; a 401 is "not logged in" (`anonymous`, no error, no `session_ended`); with no CSRF value at all it is `anonymous` without a request. A 403 rejects with `SpAuthError('csrf_failed')` and leaves the state alone (a setup error, see below); a network error or 5xx rejects too, so call it again. For the body transport `restore()` is just `ready()`.
- **CSRF (double-submit).** Every response that sets the refresh cookie also sets a readable `sp_csrf` cookie and returns the value in the `X-SP-CSRF` response header. The client takes the header first, else `readCookie('sp_csrf')` (also exported), stores it, broadcasts it to other tabs and echoes it as the `X-SP-CSRF` request header on refresh, revoke and company switch. Names are options matching the backend's `token_endpoints.csrf`: `csrf: { header: 'X-SP-CSRF', cookie: 'sp_csrf' }`; `csrf: false` when the backend switched CSRF off. A refresh 403 never ends the session.
- **Origins.**
  - *Same host, or a same-site subdomain* (`app.example.com` → `api.example.com`): the default `SameSite=strict` works. For subdomains set `SP_JWT_REFRESH_COOKIE_DOMAIN=.example.com`, or leave it unset and list `X-SP-CSRF` in CORS `exposed_headers` so the response header is readable.
  - *Different site:* `SP_JWT_REFRESH_COOKIE_SAME_SITE=none` (forces `Secure`), CORS `supports_credentials` with exact origins, and **`X-SP-CSRF` in `exposed_headers`** (the host's `config/cors.php`; the package cannot set it). Without it the browser hides the header, the client has no value and refresh answers 403: `csrf_failed`, whose message names `exposed_headers`.
- **Tabs.** The cookie is shared, each tab's access token is in its own memory. Refreshes take the cross-tab lock; the tab that refreshed broadcasts the new access token (and CSRF value, never a refresh token), and a tab waiting for the lock uses it instead of refreshing again. Tokens are broadcast, and accepted, only in a real browser tab (a `document`, a `BroadcastChannel`, a `webStorageStore` or explicit `crossTab` key).
- **Browser only.** On a server there is no cookie jar and no `document`: the cookie is never read, nothing is broadcast, `restore()` stays `anonymous` without throwing (so SSR of client components renders). Node, Express and NestJS keep the server modes and the per-request pattern below. **Server rendering with user data** (Next.js server components, Nuxt, SvelteKit, Astro, Angular SSR) still needs an access token on the server, so those apps keep the route-handler pattern in [Next.js](#nextjs-and-other-server-rendering-frameworks).

## Servers: one instance per request

Never share an auth client, or its store, between users. On a server create a client per request and drop it afterwards:

- give it its **own** `memoryStore()` (never `webStorageStore`, never a store shared with another request);
- pass `crossTab: false` (there are no tabs on a server; this also keeps the instance fully isolated);
- call `dispose()` when the request is done.

<!-- snippet:perrequest -->
```ts
// import { createJwtAuth, memoryStore, presets, userSession } from '@sopheak/sp-jwt-auth';

async function authForRequest(accessToken: string | undefined) {
  const storage = memoryStore(); // never shared between requests or users
  if (accessToken) await storage.set({ accessToken });
  return createJwtAuth({
    baseUrl: 'https://api.example.com',
    ...presets.spJwtTest,
    mode: userSession({ storage, crossTab: false }), // no tabs on a server
  });
}

const requestAuth = await authForRequest('token-from-the-incoming-request');
console.log(await requestAuth.getHeaders()); // { Authorization: 'Bearer token-from-the-incoming-request' }
requestAuth.dispose?.();
```

A token seeded without a refresh token is never refreshed: once it expires the session ends and `getHeaders()` returns `{}`.

`userSession()` with no `storage` gets a fresh `memoryStore()` per call, so on a server it simply has no tokens and never touches `localStorage`. For a token your server already holds, `staticToken` (below) is the more direct per-request mode.

### Server modes

For Node, Express, NestJS and the server side of meta-frameworks. They touch no browser globals and persist nothing.

| Mode | For | Behaviour |
|---|---|---|
| `staticToken(getToken)` | Server code that already has a user's token (a cookie read in a server component, a forwarded `Authorization` header) | `getToken()` is called on **every** `getHeaders()` / `getAccessToken()`, never cached; an empty, `null` or `undefined` result means `{}`. A 401 is final (`handleUnauthorized()` resolves `false`): refreshing is the caller's job. **Create one per request.** |
| `clientCredentials({ clientId, clientSecret, scope, tokenUrl?, auth?, defaultTtlSeconds? })` | A server calling Laravel as itself | POSTs `grant_type=client_credentials` to `tokenUrl` (default `endpoints.oauthToken`, `/oauth/token`), client authentication `auth: 'basic'` (default) or `'body'`. The token stays in memory, is re-fetched before expiry (`defaultTtlSeconds`, default 3600, when the server sends no positive `expires_in`) and on a 401, with one request in flight. One instance per process. |
| `apiKey(key)` | A static API key | Sends `Authorization: Bearer <key>`; a 401 is final. One instance per process. |

- **`logout()` is local only** in these modes: the instance stops sending the token, no request is made and nothing is revoked server-side.
- **A user's token never goes in a shared instance.** Create the `staticToken` client per request and drop it afterwards, or the next request runs as the previous user. `clientCredentials` and `apiKey` act as the server itself, so one per process is right.

<!-- snippet:statictoken -->
```ts
// import { createJwtAuth, presets, staticToken } from '@sopheak/sp-jwt-auth';

function authForIncomingRequest(req: { headers: Record<string, string | undefined> }) {
  return createJwtAuth({
    baseUrl: 'https://api.example.com',
    ...presets.spJwtTest,
    mode: staticToken(() => req.headers.authorization?.replace(/^Bearer /i, '')), // read on every call
  });
}

const userAuth = authForIncomingRequest({ headers: { authorization: 'Bearer user-token' } });
console.log(await userAuth.getHeaders()); // { Authorization: 'Bearer user-token' }
await userAuth.whoami(); // GET /me as that user
```

Still coming in later releases: the `otp`, `mfa`, `sessions`, `oauth` (authorization code, introspection, revocation), `social`, `account` and `verify` modules. They are described in the design spec but ship later.

### Next.js (and other server-rendering frameworks)

Which pattern fits depends on whether the **server** renders user data.

- **Only client components load user data:** use the [cookie transport](#cookie-transport-httponly-refresh-cookie) against Laravel directly, like an SPA, with no route handler (cross-site needs `X-SP-CSRF` in CORS `exposed_headers`). The body-transport quick start also works there, like a Vue SPA.
- **Server components load user data:** keep the tokens in **httpOnly cookies set by a Next route handler**. The handler proxies login, refresh and logout to Laravel and sets the app's *own* cookies; server components read that cookie and use the access token (with a per-request `staticToken`, see [Server modes](#server-modes)); client components call the route handler, not Laravel, for refresh. Laravel's own refresh cookie belongs to Laravel's path, so the server cannot read it, which is why the route handler stays even with the cookie transport.
- The same split applies to Nuxt, SvelteKit, Astro and Angular SSR.

The login route handler, illustrative and **not executed** (not part of the test suite; the cookie names, URL and error handling are yours to decide):

```ts
// app/api/auth/login/route.ts: illustrative, not executed
import { cookies } from 'next/headers';
import { NextResponse } from 'next/server';

const LARAVEL = process.env.LARAVEL_URL!;

export async function POST(req: Request) {
  const res = await fetch(`${LARAVEL}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: await req.text(), // credentials pass straight through
  });
  if (!res.ok) return new NextResponse(await res.text(), { status: res.status });

  const { token } = await res.json(); // sp-jwt-test shape: { user, token: { access_token, refresh_token, expires_in } }
  const jar = await cookies();
  const base = { httpOnly: true, secure: true, sameSite: 'lax', path: '/' } as const;
  jar.set('sp_access', token.access_token, { ...base, maxAge: token.expires_in });
  jar.set('sp_refresh', token.refresh_token, { ...base, path: '/api/auth', maxAge: 60 * 24 * 3600 });
  return NextResponse.json({ ok: true }); // never return the tokens to the browser
}
// A sibling /api/auth/refresh handler POSTs { refresh_token } from the sp_refresh cookie to Laravel,
// stores the rotated pair the same way, and /api/auth/logout clears both cookies.
```

## Refresh rules

The package follows these rules so apps do not each get them wrong differently (spec §4.5):

1. **Proactive.** `getAccessToken()` (and so `getHeaders()`) refreshes first when the token expires in fewer than `refreshAheadSeconds` seconds (default 60), or is already past expiry. Expiry is the JWT `exp`, falling back to `expires_in`.
2. **Single flight.** Concurrent callers share one refresh. Every refresh **rotates** the refresh token and presenting an old one counts as reuse, which by default revokes the whole session, so two parallel refreshes would log the user out. The client never lets that happen.
3. **Across tabs.** Refreshes take a lock (Web Locks, with an in-process fallback) and re-read storage inside it, adopting a pair another tab already rotated. Login, refresh and logout are broadcast (`BroadcastChannel`, with the `storage` event as a fallback), so other tabs update without a request.
4. **A 401 on a request** goes through `handleUnauthorized()`: one shared refresh, then the request may be retried **once**. If the failed request's bearer token is older than the stored one, a refresh already happened and it simply retries.
5. **Failure.** A refresh answered 401 ends the session: storage cleared (the device id is kept), state `anonymous`, a `session_ended` event, `getAccessToken()` resolves `null`. A network error, timeout or 5xx keeps the tokens and rejects the current call, since the session is not over because the network blinked.

### `crossTab`

| `userSession({ crossTab })` | Behaviour |
|---|---|
| omitted, with `webStorageStore` | **on**: lock and channel named after the store's key |
| omitted, with `memoryStore` or a custom store | store-scoped in-process lock only (instances over the same store object take turns; no channel, no globals) |
| `true` or `{ key }` | on with that key |
| `{ instance }` | a ready-made cross-tab object you manage yourself |
| `false` | per-instance single flight only |

**On a server pass `crossTab: false`** and a fresh `memoryStore()` per request. Call `auth.dispose()` when a client is discarded: it unsubscribes and closes the channel (idempotent; do not use the client afterwards).

## Presets

`presets.spJwtTest` and `presets.speedxSaas` are frozen `{ endpoints, unwrap }` objects to spread into the options next to your own `baseUrl` and `mode`:

```ts
createJwtAuth({ baseUrl, ...presets.speedxSaas, mode: userSession({ storage }) });
// override one route:
createJwtAuth({ baseUrl, ...presets.spJwtTest, endpoints: { ...presets.spJwtTest.endpoints, whoami: '/profile' }, mode });
```

| Preset | Routes | Response shape |
|---|---|---|
| `spJwtTest` | login `/auth/login`, refresh `/auth/refresh`, logout `/auth/logout`, whoami `/me` | `{ user, token: { … } }`, no envelope (`unwrap: 'raw'`) |
| `speedxSaas` | login, `/auth/login/2fa`, refresh, logout, whoami, `/auth/impersonate_in` (company switch), forgot/reset password, resend verification | `{ success, data }` envelope (`unwrap: 'sp-laravel-api'`) |

Routes you do not configure make the feature that needs them reject with `SpAuthError('not_configured')`.

## Revocation limit

The Laravel backend checks the token's `jti` row in the database on **every request**, so a logout or revocation takes effect at once for calls that reach Laravel. Anything that only verifies the JWT signature (a JWKS-only check in another service) cannot see revocations: such a token stays acceptable until it expires (15 minutes by default). Treat client-side claims (`getState().claims`, `hasScope()`) as UI hints; the server decides. `logout()` clears local state first and revokes server-side best effort, so an offline or failing revoke never leaves the UI signed in.

## Error codes

Every failed call rejects with one `SpAuthError` (`status`, `code`, `message`, `module`, `fieldErrors`, `requestId`, `retryAfter`, `body`, `response`). Narrow with `isSpAuthError(e)` and branch on `code`. RFC 6749 codes from an OAuth server (for example `invalid_client`) are passed through as `code` unchanged.

| Code | Meaning |
|---|---|
| `session_ended` | The session is over (refresh answered 401, or nothing to refresh with). State is `anonymous`. |
| `second_factor_required` | A second factor is needed to finish signing in. |
| `invalid_code` | HTTP 422: a validation failure or a wrong code; see `fieldErrors`. |
| `rate_limited` | HTTP 429; `retryAfter` holds the seconds when the server sent `Retry-After`. |
| `delivery_failed` | HTTP 502: the server could not deliver a code (SMS or e-mail). |
| `not_configured` | A route or option the call needs is not set (or the mode cannot do it). |
| `module_disabled` | HTTP 404 on a module's route: the host has switched that module off. |
| `csrf_failed` | HTTP 403 on a cookie-transport refresh: the `X-SP-CSRF` header is missing or wrong (a setup error; the session and state are kept). Cross-site, check CORS `exposed_headers`. |
| `invalid_token` | A token was rejected or malformed. |
| `network` | The request failed before a response (offline, DNS, CORS). |
| `timeout` | The request exceeded `timeoutMs`. |
| `unknown` | Anything else; read `status` and `body`. |

## Modules

Each module is a function that takes the core auth object. **Only the core (session, cookie transport and the server modes) ships in 0.1**; the rest are coming in later releases.

| Backend module | Import path | Client provides | Status |
|---|---|---|---|
| Core: `JwtTokenService`, guard, `TokenContext`; `token_endpoints`; host login / 2FA | `@sopheak/sp-jwt-auth` | `createJwtAuth`, `userSession`, state/subscribe, `memoryStore` / `webStorageStore`, refresh rules, `getHeaders`, `handleUnauthorized`, scope checks, claims, single flight, cross-tab lock, `login`, `verifySecondFactor`, `logout`, `whoami`, `switchCompany`, `presets`, cookie transport (`transport: 'cookie'`, `restore()`, `readCookie`) | **0.1** |
| `api_keys` | `@sopheak/sp-jwt-auth` (core) | `apiKey()` mode | **0.1** |
| (server tokens) | `@sopheak/sp-jwt-auth` (core) | `staticToken()` mode | **0.1** |
| `first_factor_otp` | `@sopheak/sp-jwt-auth/otp` | `otp(auth)` | coming later |
| `mfa` | `@sopheak/sp-jwt-auth/mfa` | `mfa(auth).resend(challenge)` | coming later |
| Sessions | `@sopheak/sp-jwt-auth/sessions` | `sessions(auth)` | coming later |
| `oauth_server` | `@sopheak/sp-jwt-auth` (core) | `clientCredentials()` mode | **0.1** |
| `oauth_server` | `@sopheak/sp-jwt-auth/oauth` | `oauthAuthorizationCode` mode, `introspect`, `revoke` | coming later |
| `external_identities` | `@sopheak/sp-jwt-auth/social` | `social(auth)` | coming later |
| `password_reset`, `email_verification` | `@sopheak/sp-jwt-auth/account` | `account(auth)` | coming later |
| `keys` / JWKS | `@sopheak/sp-jwt-auth/verify` | `createVerifier` (optional peer `jose`) | coming later |

## Backend compatibility

| `@sopheak/sp-jwt-auth` | `sopheak/sp-jwt-auth` (Laravel) |
|---|---|
| `0.1` | `^0.1.25` |

Older hosts (0.1.24) still work because the client does not rely on what 0.1.25 fixed: it refreshes ahead of expiry (0.1.24 applied no JWT clock-skew leeway) and treats `expires_in: 0` as "unknown" rather than "already expired" (0.1.24 returned 0 for OAuth tokens under Carbon 3). The contract tests against the `sp-jwt-test` backend are written but not yet run or recorded; they stay skipped until fixtures exist, so this table is the intended support range, not a verified one.

## License

MIT. Copyright (c) 2026 Sem Sopheak.
