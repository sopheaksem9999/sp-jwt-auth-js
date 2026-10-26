// Contract test for `sessions(auth)` against the sp-jwt-test backend (host session routes).
// Live when SP_CONTRACT_URL is set; otherwise replays test/fixtures/<backend-version>/. With neither a backend nor
// fixtures the whole suite is SKIPPED (never silently passing).
import { describe, expect, it } from 'vitest';
import { createJwtAuth, memoryStore, presets, userSession } from '../../src';
import { sessions } from '../../src/sessions';
import { liveOrReplay } from '../support/replay';

const { fetch: contractFetch, mode, baseUrl, hasFixtures } = liveOrReplay();

describe.skipIf(mode !== 'live' && !hasFixtures)('sessions contract (sp-jwt-test)', () => {
  // UNVERIFIED-CONTRACT: never run against a live backend yet; the host session routes and the list shape are assumed.
  it('list returns the signed-in session marked current', async () => {
    const auth = createJwtAuth({
      baseUrl,
      ...presets.spJwtTest,
      endpoints: { ...presets.spJwtTest.endpoints, sessions: '/auth/sessions' },
      mode: userSession({ storage: memoryStore() }),
      fetch: contractFetch,
    });
    try {
      await auth.login({
        email: process.env.SP_CONTRACT_EMAIL ?? 'user@example.test',
        password: process.env.SP_CONTRACT_PASSWORD ?? 'replay-password',
      });
      const list = await sessions(auth).list();
      expect(list.length).toBeGreaterThan(0);
      expect(list.filter((s) => s.current)).toHaveLength(1);
    } finally {
      auth.dispose?.();
    }
  });
});
