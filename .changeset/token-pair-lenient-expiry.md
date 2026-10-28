---
"@sokpheak/sp-jwt-auth": patch
---

A token pair now needs only a non-empty `access_token`: a missing, non-numeric or negative `expires_in` is treated as no expiry (numeric strings are parsed) instead of failing the login or refresh. The JWT `exp` still takes precedence.
