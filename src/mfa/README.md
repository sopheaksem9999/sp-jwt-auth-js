# `@sopheak/sp-jwt-auth/mfa`

Client for the backend's `mfa` OTP challenge brokers (`MfaChallengeBroker`, `OtpChallengeBroker`). The package ships brokers only, **no routes**: the resend route is host code, so you set `endpoints.secondFactorResend`. (The SaaS host answers this in its own 2FA controller; there is no package file:line to mirror. The request bodies follow the second-factor step, `docs/tutorials/login-with-mfa.md:46-70`.)

```ts
import { mfa } from '@sopheak/sp-jwt-auth/mfa';

const result = await auth.login(credentials);
if (result.status === 'second_factor_required') {
  await mfa(auth).resend(result.challenge);
  await auth.verifySecondFactor(result.challenge, code); // verifying a code is core, not this module
}
```

`mfa(auth).resend(challenge)` POSTs to `endpoints.secondFactorResend`, unauthenticated, with `{ '2fa_token': token }` (challenge kind `'2fa_token'`) or `{ challenge_id: token }` (kind `'challenge_id'`), and returns the response body as is (no unwrap, no token handling).

## Errors (`SpAuthError`, `module: 'mfa'`)

| Status | `code` |
|---|---|
| `endpoints.secondFactorResend` unset | `not_configured` (no request is made) |
| 422 | `invalid_code` |
| 429 | `rate_limited` (`retryAfter`) |
| 502 | `delivery_failed` |
| network / timeout | `network` / `timeout` |
