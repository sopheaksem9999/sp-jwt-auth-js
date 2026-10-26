// Contract test for `mfa(auth).resend` against the sp-jwt-test backend (the host's second-factor resend route).
// Live when SP_CONTRACT_URL is set; otherwise replays test/fixtures/<backend-version>/. With neither a backend nor
// fixtures the whole suite is SKIPPED (never silently passing).
import { describe, expect, it } from 'vitest';
import { createJwtAuth, memoryStore, presets, userSession } from '../../src';
import { mfa } from '../../src/mfa';
import { liveOrReplay } from '../support/replay';

const { fetch: contractFetch, mode, baseUrl, hasFixtures } = liveOrReplay();

describe.skipIf(mode !== 'live' && !hasFixtures)('mfa contract (sp-jwt-test)', () => {
  // UNVERIFIED-CONTRACT: never run against a live backend yet; the resend route path and body are assumed.
  it('resend answers for a challenge_id issued by the host login', async () => {
    const auth = createJwtAuth({
      baseUrl,
      ...presets.spJwtTest,
      endpoints: { ...presets.spJwtTest.endpoints, secondFactorResend: '/auth/login/2fa/resend' },
      mode: userSession({ storage: memoryStore() }),
      fetch: contractFetch,
    });
    try {
      const res = await auth.login({
        email: process.env.SP_CONTRACT_MFA_EMAIL ?? 'mfa@example.test',
        password: process.env.SP_CONTRACT_MFA_PASSWORD ?? 'replay-password',
      });
      expect(res.status).toBe('second_factor_required');
      if (res.status !== 'second_factor_required') return;
      await expect(mfa(auth).resend(res.challenge)).resolves.not.toThrow();
    } finally {
      auth.dispose?.();
    }
  });
});
