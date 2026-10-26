---
'@sopheak/sp-jwt-auth': patch
---

Errors no longer leak response data through `cause` or `body`: an invalid token pair (login, second factor, otp verify, company switch, OAuth code exchange) throws `unknown` with no `body`, and every `cause` that is not a plain transport failure (refresh, CSRF, verify, mfa, unwrap errors) is replaced by a copy holding only name, status and code.
