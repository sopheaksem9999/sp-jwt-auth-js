// Contract test for `social(auth)` against the sp-jwt-test backend (host social routes).
// Live when SP_CONTRACT_URL is set; otherwise replays test/fixtures/<backend-version>/. With neither a backend nor
// fixtures the whole suite is SKIPPED (never silently passing).
import { describe, expect, it } from 'vitest';
import { createJwtAuth, memoryStore, presets, userSession } from '../../src';
import { social } from '../../src/social';
import { liveOrReplay } from '../support/replay';

const { fetch: contractFetch, mode, baseUrl, hasFixtures } = liveOrReplay();

describe.skipIf(mode !== 'live' && !hasFixtures)('social contract (sp-jwt-test)', () => {
  // UNVERIFIED-CONTRACT: never run against a live backend yet; the host callback route and its params are assumed.
  it('completeFromCallback signs in with a provider callback code', async () => {
    const auth = createJwtAuth({
      baseUrl,
      ...presets.spJwtTest,
      endpoints: { ...presets.spJwtTest.endpoints, socialCallback: '/auth/:provider/callback' },
      mode: userSession({ storage: memoryStore() }),
      fetch: contractFetch,
    });
    try {
      await social(auth).completeFromCallback('google', {
        code: process.env.SP_CONTRACT_SOCIAL_CODE ?? 'replay-code',
        state: process.env.SP_CONTRACT_SOCIAL_STATE ?? 'replay-state',
      });
      expect(auth.getState().status).toBe('authenticated');
    } finally {
      auth.dispose?.();
    }
  });
});
