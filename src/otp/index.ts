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
  otp_id: string;
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

const MODULE = 'otp';

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/**
 * The sent descriptor from a raw body: the configured `unwrap` first, then (when
 * that value has no `otp_id`) the raw body and one `{ data }` level of it.
 */
function toSent(auth: JwtAuth, raw: unknown): OtpSent | null {
  const unwrapped = auth.unwrap(raw);
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
 */
export function otp(auth: JwtAuth): OtpModule {
  const route = (suffix: string): string => `${auth.endpoint('otp', MODULE).replace(/\/+$/, '')}${suffix}`;

  const send = async (suffix: string, body: unknown): Promise<OtpSent> => {
    const { body: raw } = await auth.http<unknown>({
      method: 'POST',
      endpoint: route(suffix),
      body,
      bearer: false,
      module: MODULE,
      disabledOn404: true,
    });
    const sent = toSent(auth, raw);
    if (!sent) {
      throw new SpAuthError({ status: 0, code: 'unknown', message: 'Response did not describe a sent OTP', module: MODULE });
    }
    return sent;
  };

  return {
    request: (b) => send('/request', b),
    resend: (b) => send('/resend', b),
    resendByDestination: (b) => send('/resend-by-destination', b),
    async verify(b) {
      const { body, response } = await auth.http<unknown>({
        method: 'POST',
        endpoint: route('/verify'),
        body: b,
        bearer: false,
        device: true,
        credentials: auth.credentials,
        module: MODULE,
        disabledOn404: true,
      });
      await auth.acceptTokens(body, response);
    },
  };
}
