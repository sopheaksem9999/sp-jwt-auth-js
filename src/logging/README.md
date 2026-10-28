# `@sokpheak/sp-jwt-auth/logging`

Optional request logging. Off by default and not part of the main entry: you only pay for it when you import this subpath. The package never writes output itself; the sink is yours.

```ts
import { createJwtAuth, userSession } from '@sokpheak/sp-jwt-auth';
import { createAuthLogger } from '@sokpheak/sp-jwt-auth/logging';

const auth = createJwtAuth({
  baseUrl: 'https://api.example.com',
  mode: userSession({ crossTab: false }),
  logger: createAuthLogger({ sink: (entry) => console.log(entry) }),
  logRequests: true, // the global switch
});
```

Entries are produced only when a `logger` is set AND `logRequests` is `true`. One `AuthLogEntry` per HTTP call made through the client (login, refresh, revoke, `whoami`, second factor, OTP, MFA, social, `auth.http`): `method`, `path`, `status` (`null` when no response arrived), `durationMs`, `requestId`, `attempt` (always `1`), `code`, `errorCode`.

**Bodies, headers and query strings are never logged**, and no option turns that on.

- `path` is the pathname only and is logged verbatim (a session id segment appears as is).
- `requestId` is the `X-Request-Id` header, else the body's `meta.request_id`, cleaned of control characters and cut to 128 characters.
- `code` is the `SpAuthError` code (`aborted` for a caller abort); `errorCode` is the response body's numeric `error_code`. A 200 `{ success: false }` response is logged as `code: 'request_failed'`; the call itself is unchanged.
- The sink runs inline: keep it quick. A throw or a rejected promise from it is ignored.
