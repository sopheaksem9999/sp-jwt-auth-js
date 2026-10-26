---
'@sopheak/sp-jwt-auth': minor
---

New modules `@sopheak/sp-jwt-auth/sessions`, `/account` and `/social` (host-owned routes configured under `endpoints`). `sessions(auth, { method?, revokeOthersBody? })`: `list()` (marks the entry whose id equals the JWT `sid` as `current`), `revoke(sid)` (clears the local session when it is the current one), `revokeOthers()` (sends `{ except_sid }`; refuses without a current `sid`), `revokeDevice(deviceId)`. `account(auth)`: `forgotPassword`, `resetPassword` (clears the local session on success), `resendVerification`, `verifyEmail`. `social(auth)`: `redirectUrl(provider)` and `completeFromCallback(provider, params)` (stores the returned pair). Path placeholders are URL-encoded. `JwtAuth` gains the internal `baseUrl` module-surface member.
