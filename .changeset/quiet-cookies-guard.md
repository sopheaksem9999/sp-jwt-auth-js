---
'@sopheak/sp-jwt-auth': minor
---

Cookie transport: `userSession({ transport: 'cookie', csrf? })` keeps the refresh token in the backend's httpOnly cookie (never read, stored or sent by the client; a body `refresh_token` is dropped), the access token in memory, and only `csrf` / `deviceId` / `lastCompanyId` in storage. CSRF double-submit (`X-SP-CSRF` response header first, else the `sp_csrf` cookie via the new `readCookie`), `JwtAuth.restore()` for page load, `csrf_failed` on a 403 with a CORS `exposed_headers` hint, cross-tab adoption of a broadcast access token inside the refresh lock, and logout with the bearer and the cookie. `whoami` no longer attaches a user fetched for a subject that has since changed.
