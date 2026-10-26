---
'@sopheak/sp-jwt-auth': patch
---

Cookie transport: a tab that had to wait for the cross-tab refresh lock no longer rotates a second time when the other tab's `BroadcastChannel` message arrives just after the lock grant (browsers do not order the two). After a contended grant with no fresh token yet, it waits up to the new `userSession({ broadcastGraceMs })` (default 100 ms, `0` turns it off) for the broadcast, continuing as soon as a message arrives; uncontended refreshes never wait, the lock is held at most that much longer, and `dispose()` ends a pending wait. `CrossTab.withLock` callbacks now receive `{ contended }` (Web Locks are probed with `ifAvailable` first; lock managers without that form still work and report uncontended).
