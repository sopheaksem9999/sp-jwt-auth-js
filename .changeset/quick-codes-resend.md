---
'@sopheak/sp-jwt-auth': minor
---

New modules `@sopheak/sp-jwt-auth/otp` (`otp(auth).request / resend / resendByDestination / verify` for the backend's first-factor OTP; `verify` stores the token pair) and `@sopheak/sp-jwt-auth/mfa` (`mfa(auth).resend(challenge)` to `endpoints.secondFactorResend`). Core additions for modules: `HttpRequest.disabledOn404` and `JwtAuth.credentials`.
