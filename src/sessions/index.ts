import { SpAuthError, sanitizedCause } from '../core/errors';
import type { JwtAuth } from '../core/types';

/** One active session as the host returns it; unknown host fields pass through. */
export interface Session {
  /** Session id (the JWT `sid` claim of that session's tokens). */
  id: string;
  /** `true` when `id` equals the `sid` claim of the current access token (compared as strings). */
  current: boolean;
  deviceId?: string;
  deviceName?: string;
  ip?: string;
  userAgent?: string;
  createdAt?: string;
  lastActiveAt?: string;
  [k: string]: unknown;
}

/** Options for `sessions(auth, options)`. */
export interface SessionsOptions {
  /** HTTP method of `revoke` and `revokeDevice`; default `'DELETE'` (the spec allows POST or DELETE: it is a host route). */
  method?: 'POST' | 'DELETE';
  /**
   * Body of `revokeOthers`. Receives the current `sid` (`null` when the token has none)
   * and replaces the default `{ except_sid: sid }`. With it set, the no-`sid` check is yours.
   */
  revokeOthersBody?: (sid: string | null) => Record<string, unknown>;
}

/** The `sessions(auth)` module surface. */
export interface SessionsModule {
  /** `GET endpoints.sessions`: the user's active sessions, the current one marked `current: true`. */
  list(): Promise<Session[]>;
  /**
   * `DELETE endpoints.sessionRevoke` (`:sid` replaced, URL-encoded). When `sid` is the
   * current session the local session is cleared after success (the token is dead).
   */
  revoke(sid: string): Promise<void>;
  /**
   * `POST endpoints.sessionRevokeOthers` with `{ except_sid: <current sid> }` (host-defined
   * default, see `revokeOthersBody`). Throws `not_configured` ("no current session id") without a
   * request when the access token has no `sid`: an empty exception would revoke this session too.
   */
  revokeOthers(): Promise<void>;
  /** `DELETE endpoints.deviceRevoke` (`:deviceId` replaced, URL-encoded). */
  revokeDevice(deviceId: string): Promise<void>;
}

const MODULE = 'sessions';

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function unknownError(message: string, cause?: unknown): SpAuthError {
  // No `body`; the cause is reduced to name/status/code (a malformed response may carry secrets).
  return new SpAuthError({ status: 0, code: 'unknown', message, module: MODULE, cause: sanitizedCause(cause) });
}

/** Replaces `:name` in a configured route with the URL-encoded value; dot segments and empty values are refused. */
function fill(endpoint: string, name: string, value: unknown): string {
  if (typeof value !== 'string' || value === '' || value === '.' || value === '..') {
    throw new SpAuthError({ status: 0, code: 'invalid_request', message: `Invalid ${name}`, module: MODULE });
  }
  return endpoint.replace(`:${name}`, () => encodeURIComponent(value));
}

/**
 * Session and device revocation (backend `JwtTokenService::activeSessionsForUser`,
 * `revokeSession`, `revokeAllForUser`, `revokeDevice`; mirrors
 * `src/Services/JwtTokenService.php:252-335`). The package has no routes: they are
 * HOST-owned and configured via `endpoints.sessions`, `sessionRevoke`,
 * `sessionRevokeOthers` and `deviceRevoke`; an unset one throws `not_configured`.
 *
 * @param auth The client from `createJwtAuth`.
 */
export function sessions(auth: JwtAuth, options: SessionsOptions = {}): SessionsModule {
  const method = options.method ?? 'DELETE';
  const currentSid = (): string | null => {
    const sid = auth.decodeClaims()?.sid;
    return sid === undefined || sid === null || sid === '' ? null : String(sid);
  };

  return {
    async list() {
      const endpoint = auth.endpoint('sessions', MODULE);
      const { body: raw } = await auth.http<unknown>({ method: 'GET', endpoint, bearer: true, module: MODULE });
      let value: unknown;
      try {
        value = auth.unwrap(raw);
      } catch (cause) {
        throw unknownError('Response could not be unwrapped', cause);
      }
      if (isRecord(value)) {
        const inner = Array.isArray(value.data) ? value.data : value.sessions;
        if (Array.isArray(inner)) value = inner;
      }
      if (!Array.isArray(value) || !value.every(isRecord)) throw unknownError('Response was not a list of sessions');
      const sid = currentSid();
      return value.map((s) => ({ ...s, current: sid !== null && s.id !== undefined && s.id !== null && String(s.id) === sid }) as Session);
    },

    async revoke(sid) {
      const endpoint = fill(auth.endpoint('sessionRevoke', MODULE), 'sid', sid);
      const wasCurrent = currentSid() === sid;
      await auth.http<unknown>({ method, endpoint, bearer: true, module: MODULE });
      if (wasCurrent) await auth.clearSession();
    },

    async revokeOthers() {
      const endpoint = auth.endpoint('sessionRevokeOthers', MODULE);
      const sid = currentSid();
      let body: Record<string, unknown>;
      if (options.revokeOthersBody) {
        body = options.revokeOthersBody(sid);
      } else {
        if (sid === null) throw new SpAuthError({ status: 0, code: 'not_configured', message: 'No current session id (the access token has no sid claim)', module: MODULE });
        body = { except_sid: sid };
      }
      await auth.http<unknown>({ method: 'POST', endpoint, body, bearer: true, module: MODULE });
    },

    async revokeDevice(deviceId) {
      const endpoint = fill(auth.endpoint('deviceRevoke', MODULE), 'deviceId', deviceId);
      await auth.http<unknown>({ method, endpoint, bearer: true, module: MODULE });
    },
  };
}
