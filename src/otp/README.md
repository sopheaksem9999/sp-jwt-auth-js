# `@sokpheak/sp-jwt-auth/otp`

Client for the backend's `first_factor_otp` module (config flag `sp-jwt-auth.first_factor_otp.enabled`, **off by default**). Mirrors `routes/otp.php` of `sopheak/sp-jwt-auth` (`request` :12-40, `resend` :42-66, `resend-by-destination` :68-88, `verify` :90-131).

```ts
import { otp } from '@sokpheak/sp-jwt-auth/otp';

const codes = otp(auth);
const sent = await codes.request({ destination: 'a@example.com', channel: 'email', purpose: 'login' });
await codes.resend({ otp_id: sent.otp_id, destination: 'a@example.com', channel: 'email' });
await codes.resendByDestination({ destination: 'a@example.com', channel: 'email', purpose: 'login' });
await codes.verify({ otp_id: sent.otp_id, code: '123456' });
```

| Method | Route (under `endpoints.otp`, default `/otp`) | Result |
|---|---|---|
| `request(b)` | `POST /request` | `OtpSent` `{ otp_id, destination_masked, expires_in }` (HTTP **202** is success) |
| `resend(b)` | `POST /resend` | `OtpSent` |
| `resendByDestination(b)` | `POST /resend-by-destination` | `OtpSent` |
| `verify(b)` | `POST /verify` | `void`; the token pair is stored through `auth.acceptTokens` |

- `request`, `resend` and `resendByDestination` are unauthenticated and send no device headers. `verify` issues tokens: it sends the device headers (when the `device` option is set) and `credentials: 'include'` in cookie mode, and passes the response to `acceptTokens` so the cookie transport drops the body refresh token and reads `X-SP-CSRF`.
- The sent descriptor is read from the body unwrapped per the client's `unwrap` option (including a function); when that has no `otp_id`, the raw body and one `{ data }` level of it are tried.
- On any `verify` failure nothing is stored and the state is unchanged. The code never appears in errors or events.

## Host-wrapped OTP (options)

`otp(auth, options?)` accepts optional hooks for a flow that the host app wraps. With no options everything above is unchanged.

```ts
const codes = otp(auth, {
  routes: { request: '/api/login/otp', verify: '/api/login/otp/check' }, // full paths, per route
  requestBody: (b) => ({ to: b.destination, kind: b.purpose }),
  challengeIdFrom: (res) => (res as { data?: { challenge?: string } }).data?.challenge ?? null,
  verifyBody: (b, challengeId) => ({ challenge: challengeId, pin: b.code }),
});
```

- `routes` overrides `${endpoints.otp}${suffix}` per route; unset routes keep the defaults.
- `requestBody(b)` builds the `request` body. `verifyBody(b, challengeId)` builds the `verify` body.
- `challengeIdFrom(response)` reads an id from the raw response of a successful send (never called when the send fails, including a 200 `{ success: false }`). The module keeps it: every `request` resets it, `resend` and `resendByDestination` keep the previous one when the response has none, a successful `verify` clears it.
- When `challengeIdFrom` is set, a send response need not look like `OtpSent`: the returned descriptor is best-effort (`otp_id` from the response or the captured id, else `''`; `destination_masked` `''`; `expires_in` `0`). Without it the response stays strict.
- `OtpVerifyBody.otp_id` became optional (type loosening); omitting it without options is a runtime 422 from the backend.
- Without `verifyBody`, the kept id is sent as `otp_id` when the caller's body has none (`otp_id` is optional on `OtpVerifyBody`).
- A throwing callback rejects with `SpAuthError` (`unknown`, module `otp`) and a fixed message; the original error text is not exposed. A throwing `challengeIdFrom` leaves the id as reset by the call.
- The kept challenge id lives in the `otp()` instance: a `request` on one instance and a `verify` on another loses it (create `otp(auth, …)` once and share it).
- The Dart second-factor branch of `verify` is not implemented (recorded divergence).

## Errors (`SpAuthError`, `module: 'otp'`)

| Status | `code` |
|---|---|
| 422 | `invalid_code` |
| 429 | `rate_limited` (`retryAfter` in seconds, from `Retry-After` as seconds or an HTTP date) |
| 502 | `delivery_failed` |
| 404 | `module_disabled` (the host keeps `first_factor_otp` off) |
| 2xx without the expected body | `unknown` |
| network / timeout | `network` / `timeout` |

`endpoints.otp` has a package default (`/otp`), so `not_configured` does not apply.
