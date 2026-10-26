// Contract tests for `otp(auth)` against the sp-jwt-test backend (first_factor_otp enabled, and one run with it off).
// Live when SP_CONTRACT_URL is set; otherwise replays test/fixtures/<backend-version>/. With neither a backend nor
// fixtures the whole suite is SKIPPED (never silently passing).
import { describe, expect, it } from 'vitest';
import { createJwtAuth, memoryStore, presets, userSession } from '../../src';
import type { JwtAuth } from '../../src';
import { SpAuthError } from '../../src';
import { otp } from '../../src/otp';
import { liveOrReplay } from '../support/replay';

const { fetch: contractFetch, mode, baseUrl, hasFixtures } = liveOrReplay();
const destination = process.env.SP_CONTRACT_OTP_DESTINATION ?? 'otp@example.test';

function client(endpoints: Record<string, string> = {}): JwtAuth {
  return createJwtAuth({
    baseUrl,
    ...presets.spJwtTest,
    endpoints: { ...presets.spJwtTest.endpoints, ...endpoints },
    mode: userSession({ storage: memoryStore() }),
    fetch: contractFetch,
  });
}

describe.skipIf(mode !== 'live' && !hasFixtures)('otp contract (sp-jwt-test)', () => {
  // UNVERIFIED-CONTRACT: never run against a live backend yet; fixtures not recorded.
  it('request answers 202 with the sent descriptor, and a wrong code is invalid_code', async () => {
    const auth = client();
    try {
      const sent = await otp(auth).request({ destination, channel: 'email', purpose: 'login' });
      expect(sent.otp_id).toBeTruthy();
      expect(typeof sent.destination_masked).toBe('string');
      expect(sent.expires_in).toBeGreaterThan(0);
      await expect(otp(auth).verify({ otp_id: sent.otp_id, code: '000000' })).rejects.toMatchObject({ code: 'invalid_code' });
      expect(auth.getState().status).not.toBe('authenticated');
    } finally {
      auth.dispose?.();
    }
  });

  it('with first_factor_otp disabled, the routes answer module_disabled', async () => {
    // UNVERIFIED-CONTRACT: the disabled backend is reached by swapping the `endpoints.otp` prefix (SP_CONTRACT_OTP_DISABLED_PREFIX, default /otp-disabled).
    const auth = client({ otp: `${process.env.SP_CONTRACT_OTP_DISABLED_PREFIX ?? '/otp-disabled'}` });
    try {
      const err = await otp(auth)
        .request({ destination, channel: 'email', purpose: 'login' })
        .catch((e: unknown) => e);
      expect(err).toBeInstanceOf(SpAuthError);
      expect(err).toMatchObject({ code: 'module_disabled', module: 'otp' });
    } finally {
      auth.dispose?.();
    }
  });
});
