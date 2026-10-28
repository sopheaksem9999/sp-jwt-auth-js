---
"@sokpheak/sp-jwt-auth": minor
---

Optional request logging (D2) in the new `@sokpheak/sp-jwt-auth/logging` subpath: `createJwtAuth({ logger: createAuthLogger({ sink }), logRequests: true })`. Off by default; entries are produced only when both `logger` and `logRequests` are set, and the main entry gains only a small hook and the `AuthLogEntry` type. One `AuthLogEntry` (`method`, `path`, `status`, `durationMs`, `requestId`, `attempt`, `code`, `errorCode`) per HTTP call made through the client (login, refresh, revoke, `whoami`, second factor, OTP, MFA, social, `auth.http`). Bodies, headers and query strings are never logged, with no option to enable them; request ids are cleaned and `code` falls back to `'unknown'` when it is not identifier-like. A sink, or a hand-written logger, that throws or rejects never changes a call's result.
