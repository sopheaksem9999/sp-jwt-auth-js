// Contract test for `createVerifier` against a real Laravel-issued token and the live
// `/.well-known/sp-jwt-auth/jwks.json`. Live when SP_CONTRACT_URL and SP_CONTRACT_TOKEN (a fresh access token) are set;
// SKIPPED otherwise (never silently passing). The JWKS route is plain JSON (no secrets), so no replay fixtures are used.
import { describe, expect, it } from 'vitest';
import { createVerifier } from '../../src/verify';
import { SpAuthError } from '../../src';

const baseUrl = (process.env.SP_CONTRACT_URL ?? '').replace(/\/+$/, '');
const token = process.env.SP_CONTRACT_TOKEN ?? '';
const issuer = process.env.SP_CONTRACT_ISSUER ?? '';
const live = baseUrl !== '' && token !== '' && issuer !== '';

describe.skipIf(!live)('verify contract (sp-jwt-test)', () => {
  // UNVERIFIED-CONTRACT: never run against a live backend yet; the issuer value (jwt.issuer config) is assumed.
  const verify = () => createVerifier({ jwksUrl: `${baseUrl}/.well-known/sp-jwt-auth/jwks.json`, issuer });

  it('verifies a real Laravel-issued access token', async () => {
    const claims = await verify()(token);
    expect(typeof claims.sub).toBe('string');
    expect(Array.isArray(claims.scopes)).toBe(true);
    expect(claims.exp).toBeGreaterThan(0);
  });

  it('rejects the same token with a tampered signature', async () => {
    const parts = token.split('.');
    parts[2] = `${parts[2]?.slice(0, -4)}AAAA`;
    await expect(verify()(parts.join('.'))).rejects.toBeInstanceOf(SpAuthError);
  });
});
