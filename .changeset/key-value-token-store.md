---
"@sokpheak/sp-jwt-auth": minor
---

Added `keyValueTokenStore(storage, keys?)`, a `TokenStore` that keeps each field under its own key in any sync or async `KeyValueStorage` (a superset of `localStorage`, so it drops in; also fits a native keychain wrapper). Key names default to `sp_access_token`, `sp_refresh_token`, `sp_access_token_expires_at`, `sp_csrf`, `sp_device_id`, `sp_last_company_id` and can be overridden via `StorageKeys`. The access token is removed first and written last, so an interrupted write reads as logged out. `get()` returns `csrf`, `deviceId` and `lastCompanyId` while logged out (never tokens), so the device id survives a restart.
