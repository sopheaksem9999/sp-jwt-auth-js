import { throwIfEnvelopeFailure } from '../core/envelope';
import { SpAuthError } from '../core/errors';
import type { JwtAuth } from '../core/types';

/** Channel an OTP code is delivered through. */
export type OtpChannel = 'email' | 'sms';

/** What the backend returns (HTTP 202) after sending or re-sending a code. */
export interface OtpSent {
  /** Identifier to pass to `resend` and `verify`. */
  otp_id: string;
  /** Destination with the middle hidden, safe to show. */
  destination_masked: string;
  /** Seconds until the code expires. */
  expires_in: number;
}

/** Body of `request`. */
export interface OtpRequestBody {
  destination: string;
  channel: OtpChannel;
  purpose: string;
  requested_type?: string;
}

/** Body of `resend`: re-sends the code of an existing `otp_id`. */
export interface OtpResendBody {
  otp_id: string;
  destination: string;
  channel: OtpChannel;
}

/** Body of `resendByDestination`: re-sends the latest code for a destination and purpose. */
export interface OtpResendByDestinationBody {
  destination: string;
  channel: OtpChannel;
  purpose: string;
}

/** Body of `verify`. `destination` and `channel` are optional and sent together to bind the code to its destination. */
export interface OtpVerifyBody {
  /** Optional when the module captured a challenge id (see `OtpOptions.challengeIdFrom`). */
  otp_id?: string;
  code: string;
  destination?: string;
  channel?: OtpChannel;
}

/** The `otp(auth)` module surface. */
export interface OtpModule {
  /** `POST {otp}/request`: sends a code. Answers 202. */
  request(b: OtpRequestBody): Promise<OtpSent>;
  /** `POST {otp}/resend`: sends the code of `otp_id` again. Answers 202. */
  resend(b: OtpResendBody): Promise<OtpSent>;
  /** `POST {otp}/resend-by-destination`: sends a new code for a destination and purpose. Answers 202. */
  resendByDestination(b: OtpResendByDestinationBody): Promise<OtpSent>;
  /**
   * `POST {otp}/verify`: checks the code and signs in. The returned pair goes
   * through `auth.acceptTokens` (stored, state `authenticated`; in cookie mode the
   * refresh token is dropped and the CSRF header is read). Resolves with nothing;
   * on any failure nothing is stored and the state is unchanged.
   */
  verify(b: OtpVerifyBody): Promise<void>;
}

/** Full-path route overrides; each replaces `${endpoints.otp}${suffix}` for that call. */
export interface OtpRoutes {
  request?: string;
  resend?: string;
  resendByDestination?: string;
  verify?: string;
}

/** Optional hooks for an OTP flow wrapped by the host app. With none, the backend routes and bodies are used as-is. */
export interface OtpOptions {
  /** Full paths overriding the default routes (per route). */
  routes?: OtpRoutes;
  /** Builds the body sent by `request` from the caller's body. */
  requestBody?(b: OtpRequestBody): Record<string, unknown>;
  /** Builds the body sent by `verify`; receives the caller's body and the captured challenge id (or `null`). */
  verifyBody?(b: OtpVerifyBody, challengeId: string | null): Record<string, unknown>;
  /**
   * Reads a challenge id from the raw response of a successful send. Called only
   * after the envelope check passed. `request` resets the kept id first, `resend`
   * keeps it when this returns `null`, and a successful `verify` clears it.
   */
  challengeIdFrom?(response: unknown): string | null;
}

const MODULE = 'otp';

/** Runs a user callback; a throw becomes a generic error that carries nothing from the original. */
function callHook<T>(name: string, fn: () => T): T {
  try {
    return fn();
  } catch {
    throw new SpAuthError({ status: 0, code: 'unknown', message: `OTP ${name} callback threw`, module: MODULE });
  }
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/**
 * The sent descriptor from a raw body: the configured `unwrap` first, then (when
 * that value has no `otp_id`) the raw body and one `{ data }` level of it.
 */
function toSent(auth: JwtAuth, raw: unknown): OtpSent | null {
  let unwrapped: unknown;
  try {
    unwrapped = auth.unwrap(raw);
  } catch {
    unwrapped = undefined; // a function-valued unwrap may throw on an unexpected body
  }
  for (const v of [unwrapped, raw, isRecord(raw) ? raw.data : undefined]) {
    if (isRecord(v) && typeof v.otp_id === 'string' && typeof v.destination_masked === 'string' && typeof v.expires_in === 'number') {
      return { otp_id: v.otp_id, destination_masked: v.destination_masked, expires_in: v.expires_in };
    }
  }
  return null;
}

/**
 * First-factor OTP module (backend module `first_factor_otp`, off by default;
 * mirrors `routes/otp.php`). Routes live under `endpoints.otp` (default `/otp`).
 * A 404 means the host switched the module off: `SpAuthError('module_disabled')`.
 *
 * @param auth The client from `createJwtAuth`.
 * @param options Optional routes, body builders and challenge id capture for a host-wrapped flow.
 */
export function otp(auth: JwtAuth, options: OtpOptions = {}): OtpModule {
  const route = (suffix: string, override: string | undefined): string =>
    override ?? `${auth.endpoint('otp', MODULE).replace(/\/+$/, '')}${suffix}`;
  let challengeId: string | null = null;

  const send = async (suffix: string, override: string | undefined, body: unknown, reset: boolean): Promise<OtpSent> => {
    if (reset) challengeId = null;
    const { body: raw } = await auth.http<unknown>({
      method: 'POST',
      endpoint: route(suffix, override),
      body,
      bearer: false,
      module: MODULE,
      disabledOn404: true,
    });
    throwIfEnvelopeFailure(raw, MODULE);
    const sent = toSent(auth, raw);
    if (!sent) {
      throw new SpAuthError({ status: 0, code: 'unknown', message: 'Response did not describe a sent OTP', module: MODULE });
    }
    if (options.challengeIdFrom) {
      const from = options.challengeIdFrom;
      const id = callHook('challengeIdFrom', () => from(raw));
      if (typeof id === 'string' && id !== '') challengeId = id;
    }
    return sent;
  };

  return {
    async request(b) {
      const build = options.requestBody;
      const body = build ? callHook('requestBody', () => build(b)) : b;
      return send('/request', options.routes?.request, body, true);
    },
    resend: (b) => send('/resend', options.routes?.resend, b, false),
    resendByDestination: (b) => send('/resend-by-destination', options.routes?.resendByDestination, b, false),
    async verify(b) {
      const build = options.verifyBody;
      let payload: unknown = b;
      if (build) payload = callHook('verifyBody', () => build(b, challengeId));
      else if (challengeId !== null && !b.otp_id) payload = { ...b, otp_id: challengeId };
      const { body, response } = await auth.http<unknown>({
        method: 'POST',
        endpoint: route('/verify', options.routes?.verify),
        body: payload,
        bearer: false,
        device: true,
        credentials: auth.credentials,
        module: MODULE,
        disabledOn404: true,
      });
      throwIfEnvelopeFailure(body, MODULE);
      await auth.acceptTokens(body, response);
      challengeId = null;
    },
  };
}
