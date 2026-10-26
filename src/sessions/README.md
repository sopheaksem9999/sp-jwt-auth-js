# `@sopheak/sp-jwt-auth/sessions`

Client for session and device revocation. Backend: `JwtTokenService::activeSessionsForUser`, `revokeSession`, `revokeAllForUser`, `revokeDevice` (`src/Services/JwtTokenService.php:252-335`), part of the core token service (no config flag). The package ships **no routes**: they are **host-owned** and configured through `endpoints`. An unset endpoint throws `SpAuthError('not_configured', module 'sessions')` with no request made.

```ts
import { sessions } from '@sopheak/sp-jwt-auth/sessions';

const s = sessions(auth);
const list = await s.list();
await s.revoke(list.find((x) => !x.current)!.id);
await s.revokeOthers();
await s.revokeDevice('device-id');
```

| Method | Endpoint | Request |
|---|---|---|
| `list()` | `endpoints.sessions` | `GET`, bearer. Body (unwrapped; a bare array, `{ data: [...] }` or `{ sessions: [...] }`) becomes `Session[]`: host fields pass through, `current` is `true` where `String(id) === String(sid claim)` |
| `revoke(sid)` | `endpoints.sessionRevoke` (`:sid`) | `DELETE` (option `method: 'POST'`), bearer. Revoking the current session clears the local session after success |
| `revokeOthers()` | `endpoints.sessionRevokeOthers` | `POST` `{ except_sid: <current sid> }`, bearer |
| `revokeDevice(deviceId)` | `endpoints.deviceRevoke` (`:deviceId`) | same method as `revoke`, bearer |

`:sid` and `:deviceId` are replaced with `encodeURIComponent(value)`; a value that is empty, `.` or `..` is rejected (`invalid_request`, no request) because a dot segment would change the path.

## Decision: `except_sid` (host-defined)

The backend's `revokeAllForUser($user, $exceptSid)` takes the session to keep, but the route is yours, so the body is this client's default `{ except_sid }`. Override it with `sessions(auth, { revokeOthersBody: (sid) => ({ ... }) })`. Without a current `sid` (opaque token, anonymous) the default throws `not_configured` ("no current session id") **before** any request: an empty exception would revoke the caller's own session. A custom `revokeOthersBody` receives `null` and decides itself.

Password reset does not revoke sessions on the backend; call `revokeAllForUser` in your reset route or `revokeOthers()` after a password change.

## Errors (`SpAuthError`, `module: 'sessions'`)

HTTP failures use the core mapping (401 `session_ended`/`invalid_token`, 429 `rate_limited`, 5xx, network/timeout). A body that is not a session list, or a throwing `unwrap`, is `unknown` with a fixed message (no body, cause reduced via `sanitizedCause`).
