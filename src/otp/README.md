# `@sopheak/sp-jwt-auth/otp`

Client for the backend's `first_factor_otp` module (config flag `sp-jwt-auth.first_factor_otp.enabled`, **off by default**). Mirrors `routes/otp.php` of `sopheak/sp-jwt-auth` (`request` :12-40, `resend` :42-66, `resend-by-destination` :68-88, `verify` :90-131).

```ts
import { otp } from '@sopheak/sp-jwt-auth/otp';

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
- The `{ data }` envelope around the sent descriptor is looked through, whatever the `unwrap` option.
- On any `verify` failure nothing is stored and the state is unchanged. The code never appears in errors or events.

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
