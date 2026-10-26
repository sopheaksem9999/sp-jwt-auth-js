---
'@sopheak/sp-jwt-auth': minor
---

First feature release (0.1): the core session. `createJwtAuth({ baseUrl, endpoints, mode, ... })` with `userSession` (body transport), `memoryStore` and `webStorageStore`, `login` / `verifySecondFactor` / `logout` / `whoami` / `switchCompany`, `getAccessToken` and `getHeaders` with proactive refresh, single-flight and cross-tab refresh (Web Locks, `BroadcastChannel`, `storage` fallback), retry-once `handleUnauthorized`, claims and scope helpers, one `SpAuthError` type with codes, the `presets` for the two known hosts, and a README covering the quick start, framework glue, server rules, refresh rules, the revocation limit and backend compatibility (`^0.1.25`). The `staticToken`, `clientCredentials` and `apiKey` modes and the feature modules (otp, mfa, sessions, oauth, social, account, verify) are not in this release.
