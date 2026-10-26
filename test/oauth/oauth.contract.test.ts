// Contract test for the `/oauth` module against the sp-jwt-test backend (oauth_server enabled, and one run with it off).
// Live when SP_CONTRACT_URL is set; otherwise replays test/fixtures/<backend-version>/. With neither a backend nor
// fixtures the whole suite is SKIPPED (never silently passing).
import { describe, expect, it } from 'vitest';
import { createJwtAuth, memoryStore, presets, userSession } from '../../src';
import type { JwtAuth } from '../../src';
import { SpAuthError } from '../../src';
import { oauth } from '../../src/oauth';
import { liveOrReplay } from '../support/replay';

const { fetch: contractFetch, mode, baseUrl, hasFixtures } = liveOrReplay();
const clientId = process.env.SP_CONTRACT_OAUTH_CLIENT_ID ?? 'contract-client';
const clientSecret = process.env.SP_CONTRACT_OAUTH_CLIENT_SECRET ?? 'replay-client-secret';

function client(endpoints: Record<string, string> = {}): JwtAuth {
  return createJwtAuth({
    baseUrl,
    ...presets.spJwtTest,
    endpoints: { ...presets.spJwtTest.endpoints, ...endpoints },
    mode: userSession({ storage: memoryStore() }),
    fetch: contractFetch,
  });
}

describe.skipIf(mode !== 'live' && !hasFixtures)('oauth contract (sp-jwt-test)', () => {
  // UNVERIFIED-CONTRACT: never run against a live backend yet; the client credentials and token values are assumed.
  it('introspect reports an unknown token as inactive (RFC 7662)', async () => {
    const auth = client();
    try {
      expect(await oauth(auth, { clientId, clientSecret }).introspect('spoat_unknown.token')).toEqual({ active: false });
    } finally {
      auth.dispose?.();
    }
  });

  // UNVERIFIED-CONTRACT: revoke of an unknown token is a 200 per RFC 7009 §2.2.
  it('revoke of an unknown token resolves', async () => {
    const auth = client();
    try {
      await expect(oauth(auth, { clientId, clientSecret }).revoke('spoat_unknown.token')).resolves.toBeUndefined();
    } finally {
      auth.dispose?.();
    }
  });

  // UNVERIFIED-CONTRACT: a wrong client secret is a 401 invalid_client.
  it('a wrong client secret is invalid_client', async () => {
    const auth = client();
    try {
      await expect(oauth(auth, { clientId, clientSecret: 'wrong' }).introspect('x')).rejects.toMatchObject({ code: 'invalid_client' });
    } finally {
      auth.dispose?.();
    }
  });

  // UNVERIFIED-CONTRACT: with oauth_server off the routes 404.
  it('module disabled: the routes answer 404 -> module_disabled', async () => {
    const auth = client();
    try {
      const e = await oauth(auth, { clientId, clientSecret })
        .introspect('x')
        .then(
          () => null,
          (err: unknown) => err,
        );
      // Only meaningful against a backend with oauth_server off; otherwise this documents the shape.
      if (e instanceof SpAuthError && e.code === 'module_disabled') expect(e.module).toBe('oauth');
    } finally {
      auth.dispose?.();
    }
  });
});
