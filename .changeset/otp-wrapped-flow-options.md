---
"@sokpheak/sp-jwt-auth": minor
---

`otp(auth, options?)` accepts optional `routes` (full-path overrides), `requestBody`, `verifyBody` and `challengeIdFrom` for an OTP flow wrapped by the host app. The module keeps an internal challenge id (per `otp()` instance): reset by every `request`, kept by `resend` when its response has none, cleared after a successful `verify`, and filled into `verify`'s `otp_id` when absent (`OtpVerifyBody.otp_id` is now optional, a type loosening: omitting it without options is a runtime 422). With `challengeIdFrom`, a send response need not look like `OtpSent` and the returned descriptor is best-effort. Without options nothing changes. The Dart second-factor branch of `verify` is intentionally not added.
