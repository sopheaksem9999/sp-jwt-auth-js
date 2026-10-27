# `@sokpheak/sp-jwt-auth/account`

Client for password reset and e-mail verification. Backend: the `PasswordResetBroker` and `EmailVerificationBroker` services (config flags `password_reset.enabled` / `email_verification.enabled`, `config/sp-jwt-auth.php:131-141`). The package ships brokers only, **no routes**: they are **host-owned** and configured through `endpoints.forgotPassword`, `resetPassword`, `resendVerification`, `verifyEmail` (SaaS: `/auth/forgot-password`, `/auth/reset-password`, `/auth/resend-email-verification`). An unset one throws `SpAuthError('not_configured', module 'account')` with no request.

```ts
import { account } from '@sokpheak/sp-jwt-auth/account';

const a = account(auth);
await a.forgotPassword({ email });
await a.resetPassword({ token, email, password, password_confirmation });
await a.resendVerification();
await a.verifyEmail({ id, hash, expires, signature });
```

| Method | Request | Bearer |
|---|---|---|
| `forgotPassword({ email })` | `POST`, body `{ email }` | no |
| `resetPassword({ token, email, password, password_confirmation })` | `POST`, exactly that body | no |
| `resendVerification()` | `POST`, no body | sent when a token is held, never required |
| `verifyEmail(params)` | `POST`, `params` as the JSON body | no (the signed params authenticate it) |

Each returns the response body unwrapped per the client's `unwrap` option; a throwing `unwrap` is `unknown` with a fixed message (no body; cause reduced via `sanitizedCause`).

After a **successful** `resetPassword` the stored session is cleared (no network): the backend does not revoke sessions on reset, so call `revokeAllForUser` in your reset route (as `sp-jwt-test` does). A failed reset leaves the session untouched. Passwords and reset tokens are never put in error messages, causes or events.
