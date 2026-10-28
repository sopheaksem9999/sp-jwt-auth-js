---
"@sokpheak/sp-jwt-auth": patch
---

**Behaviour change.** A HTTP 200 whose body is `{ success: false }` now throws `SpAuthError` with `status` 200, `code` `'request_failed'`, the body `message`, a numeric `errorCode` (from `error_code`) and `requestId` (from `meta.request_id`), for `login`, `verifySecondFactor`, the `/otp` methods, `mfa.resend` and refresh. `SpAuthError` gains `errorCode` (also filled from non-2xx envelope bodies). Callers matching `code === 'unknown'` on login, OTP or refresh failures now see `request_failed` instead; `mfa.resend` now rejects instead of resolving. A refresh that fails this way keeps the session, except `errorCode` 10002 or 10010, which end it (`refresh_rejected`) unless a newer session was stored or the user logged out meanwhile.
