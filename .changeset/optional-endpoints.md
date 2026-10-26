---
'@sopheak/sp-jwt-auth': patch
---

`JwtAuthOptions.endpoints` is optional (omitted means `{}`: package routes only, refresh `/auth/token/refresh`), so `createJwtAuth({ baseUrl, mode: staticToken(...) })` typechecks. `ModeContext.options.endpoints` is always set.
