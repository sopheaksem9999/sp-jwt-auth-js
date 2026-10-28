---
"@sokpheak/sp-jwt-auth": patch
---

`dispose()` now also clears the `subscribe` listeners, so a disposed instance no longer notifies them. A token refresh that leaves the state equal (for example an opaque token) does not notify `subscribe`; use `onEvent({ type: 'refresh' })` for that.
