// Contract test for `account(auth)` against the sp-jwt-test backend (host password-reset / verification routes).
// Live when SP_CONTRACT_URL is set; otherwise replays test/fixtures/<backend-version>/. With neither a backend nor
// fixtures the whole suite is SKIPPED (never silently passing).
import { describe, expect, it } from 'vitest';
import { createJwtAuth, memoryStore, presets, userSession } from '../../src';
import { account } from '../../src/account';
import { liveOrReplay } from '../support/replay';

const { fetch: contractFetch, mode, baseUrl, hasFixtures } = liveOrReplay();

describe.skipIf(mode !== 'live' && !hasFixtures)('account contract (sp-jwt-test)', () => {
  // UNVERIFIED-CONTRACT: never run against a live backend yet; the host routes and their answers are assumed.
  it('forgotPassword answers for a known e-mail', async () => {
    const auth = createJwtAuth({
      baseUrl,
      ...presets.spJwtTest,
      endpoints: { ...presets.spJwtTest.endpoints, forgotPassword: '/auth/forgot-password' },
      mode: userSession({ storage: memoryStore() }),
      fetch: contractFetch,
    });
    try {
      const body = await account(auth).forgotPassword({ email: process.env.SP_CONTRACT_EMAIL ?? 'user@example.test' });
      expect(body).toBeDefined();
    } finally {
      auth.dispose?.();
    }
  });
});
