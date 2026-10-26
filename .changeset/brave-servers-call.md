---
'@sopheak/sp-jwt-auth': minor
---

Server modes: `staticToken(getToken)` (a user's token the server already holds; read on every call, a 401 is final, create one per request), `clientCredentials({ clientId, clientSecret, scope, tokenUrl?, auth?, defaultTtlSeconds? })` (OAuth client credentials, in-memory token re-fetched before expiry and on a 401, single flight) and `apiKey(key)`. `logout()` is local only in all three. `userSession()` now defaults `storage` to a fresh `memoryStore()` per call.
