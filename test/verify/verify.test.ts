// Needs a local HTTP server (test/node), so it runs in the vitest `node` project only.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SignJWT, generateKeyPair } from 'jose';
import { createVerifier } from '../../src/verify';
import { SpAuthError } from '../../src';
import { publicJwk, startJwksServer } from '../node/jwks-server';
import type { JwksServer } from '../node/jwks-server';

const ISSUER = 'https://auth.example.test';

/** Fakes only `Date` (real sockets and promises keep working) so cache ages and cooldowns are controlled without sleeping. */
function useClock(): { advance(ms: number): void } {
  vi.useFakeTimers({ toFake: ['Date'] });
  return { advance: (ms) => vi.setSystemTime(Date.now() + ms) };
}
const now = () => Math.floor(Date.now() / 1000);

interface Pair {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
}

async function sign(
  key: Pair['privateKey'],
  kid: string,
  claims: Record<string, unknown> = {},
  o: { iss?: string; aud?: string; exp?: number; nbf?: number; alg?: string } = {},
): Promise<string> {
  const jwt = new SignJWT({ scopes: ['a', 'b'], sid: 's1', company_id: 7, ...claims })
    .setProtectedHeader({ alg: o.alg ?? 'RS256', kid })
    .setSubject('42')
    .setIssuer(o.iss ?? ISSUER)
    .setIssuedAt(now() - 120)
    .setExpirationTime(o.exp ?? now() + 600);
  if (o.aud !== undefined) jwt.setAudience(o.aud);
  if (o.nbf !== undefined) jwt.setNotBefore(o.nbf);
  return jwt.sign(key);
}

async function rejection(p: Promise<unknown>): Promise<SpAuthError> {
  try {
    await p;
  } catch (e) {
    expect(e).toBeInstanceOf(SpAuthError);
    return e as SpAuthError;
  }
  throw new Error('expected the promise to reject');
}

let server: JwksServer;
let k1: Pair;
let k2: Pair;

beforeEach(async () => {
  k1 = await generateKeyPair('RS256');
  k2 = await generateKeyPair('RS256');
  server = await startJwksServer([await publicJwk(k1.publicKey, 'k1')]);
});
afterEach(async () => {
  vi.useRealTimers();
  await server.close();
});

describe('createVerifier', () => {
  it('returns normalised claims for a valid token', async () => {
    const verify = createVerifier({ jwksUrl: server.url, issuer: ISSUER });
    const claims = await verify(await sign(k1.privateKey, 'k1'));
    expect(claims.sub).toBe('42');
    expect(claims.scopes).toEqual(['a', 'b']);
    expect(claims.sid).toBe('s1');
    expect(claims.company_id).toBe(7);
    expect(typeof claims.exp).toBe('number');
  });

  it('normalises a space separated scopes string to an array', async () => {
    const verify = createVerifier({ jwksUrl: server.url, issuer: ISSUER });
    const claims = await verify(await sign(k1.privateKey, 'k1', { scopes: 'read write' }));
    expect(claims.scopes).toEqual(['read', 'write']);
  });

  it('rejects a token signed by another key', async () => {
    const verify = createVerifier({ jwksUrl: server.url, issuer: ISSUER });
    const err = await rejection(verify(await sign(k2.privateKey, 'k1')));
    expect(err.code).toBe('invalid_token');
  });

  it('rejects a wrong issuer', async () => {
    const verify = createVerifier({ jwksUrl: server.url, issuer: ISSUER });
    const err = await rejection(verify(await sign(k1.privateKey, 'k1', {}, { iss: 'https://evil.test' })));
    expect(err.code).toBe('invalid_token');
  });

  it('rejects a wrong audience when audience is set, and accepts the right one', async () => {
    const verify = createVerifier({ jwksUrl: server.url, issuer: ISSUER, audience: 'api' });
    const err = await rejection(verify(await sign(k1.privateKey, 'k1', {}, { aud: 'other' })));
    expect(err.code).toBe('invalid_token');
    expect((await verify(await sign(k1.privateKey, 'k1', {}, { aud: 'api' }))).sub).toBe('42');
  });

  it('does not check the audience when none is configured', async () => {
    const verify = createVerifier({ jwksUrl: server.url, issuer: ISSUER });
    expect((await verify(await sign(k1.privateKey, 'k1', {}, { aud: 'whatever' }))).sub).toBe('42');
  });

  it('rejects an expired token', async () => {
    const verify = createVerifier({ jwksUrl: server.url, issuer: ISSUER });
    const err = await rejection(verify(await sign(k1.privateKey, 'k1', {}, { exp: now() - 60 })));
    expect(err.code).toBe('invalid_token');
  });

  it('rejects a token whose nbf is in the future', async () => {
    const verify = createVerifier({ jwksUrl: server.url, issuer: ISSUER });
    const err = await rejection(verify(await sign(k1.privateKey, 'k1', {}, { nbf: now() + 3600 })));
    expect(err.code).toBe('invalid_token');
  });

  it('rejects malformed and empty tokens without fetching the JWKS', async () => {
    const verify = createVerifier({ jwksUrl: server.url, issuer: ISSUER });
    for (const bad of ['', 'not-a-jwt', 'a.b.c', 'a.b']) {
      expect((await rejection(verify(bad))).code).toBe('invalid_token');
    }
    expect((await rejection(verify(undefined as unknown as string))).code).toBe('invalid_token');
    expect(server.requests).toBe(0);
  });

  it('never accepts alg none', async () => {
    const verify = createVerifier({ jwksUrl: server.url, issuer: ISSUER });
    const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const token = `${b64({ alg: 'none', kid: 'k1' })}.${b64({ sub: '42', iss: ISSUER, exp: now() + 600 })}.`;
    expect((await rejection(verify(token))).code).toBe('invalid_token');
  });

  it('rejects an HS256 token and HS256 configuration', async () => {
    const verify = createVerifier({ jwksUrl: server.url, issuer: ISSUER });
    const hs = await new SignJWT({})
      .setProtectedHeader({ alg: 'HS256', kid: 'k1' })
      .setSubject('42')
      .setIssuer(ISSUER)
      .setExpirationTime(now() + 600)
      .sign(new TextEncoder().encode('0123456789abcdef0123456789abcdef'));
    expect((await rejection(verify(hs))).code).toBe('invalid_token');
    expect(() => createVerifier({ jwksUrl: server.url, issuer: ISSUER, algorithms: ['HS256'] })).toThrow(TypeError);
    expect(() => createVerifier({ jwksUrl: server.url, issuer: ISSUER, algorithms: ['none'] })).toThrow(TypeError);
    expect(() => createVerifier({ jwksUrl: server.url, issuer: ISSUER, algorithms: [] })).toThrow(TypeError);
  });

  it('rejects a token signed with an algorithm that is not in the configured list', async () => {
    const ps = await generateKeyPair('PS256');
    server.setKeys([await publicJwk(ps.publicKey, 'p1', 'PS256')]);
    const token = await sign(ps.privateKey, 'p1', {}, { alg: 'PS256' });
    const strict = createVerifier({ jwksUrl: server.url, issuer: ISSUER });
    expect((await rejection(strict(token))).code).toBe('invalid_token');
    const wide = createVerifier({ jwksUrl: server.url, issuer: ISSUER, algorithms: ['RS256', 'PS256'] });
    expect((await wide(token)).sub).toBe('42');
  });

  it('verifies a token with an unknown kid after the key set is rotated', async () => {
    const clock = useClock();
    const verify = createVerifier({ jwksUrl: server.url, issuer: ISSUER, cooldownMs: 1000 });
    expect((await verify(await sign(k1.privateKey, 'k1'))).sub).toBe('42');
    server.setKeys([await publicJwk(k1.publicKey, 'k1'), await publicJwk(k2.publicKey, 'k2')]);
    clock.advance(2000);
    expect((await verify(await sign(k2.privateKey, 'k2'))).sub).toBe('42');
    expect((await verify(await sign(k1.privateKey, 'k1'))).sub).toBe('42');
  });

  it('respects the cooldown: an unknown kid inside it does not refetch', async () => {
    const clock = useClock();
    const verify = createVerifier({ jwksUrl: server.url, issuer: ISSUER, cooldownMs: 60_000 });
    await verify(await sign(k1.privateKey, 'k1'));
    expect(server.requests).toBe(1);
    server.setKeys([await publicJwk(k2.publicKey, 'k2')]);
    clock.advance(30_000);
    const err = await rejection(verify(await sign(k2.privateKey, 'k2')));
    expect(err.code).toBe('invalid_token');
    expect(server.requests).toBe(1);
    clock.advance(31_000);
    expect((await verify(await sign(k2.privateKey, 'k2'))).sub).toBe('42');
    expect(server.requests).toBe(2);
  });

  it('rejects an unknown kid as invalid_token once the cooldown has passed and the key is still absent', async () => {
    const clock = useClock();
    const verify = createVerifier({ jwksUrl: server.url, issuer: ISSUER, cooldownMs: 1000 });
    await verify(await sign(k1.privateKey, 'k1'));
    clock.advance(2000);
    const err = await rejection(verify(await sign(k2.privateKey, 'ghost')));
    expect(err.code).toBe('invalid_token');
    expect(server.requests).toBe(2);
  });

  it('keeps the last good key set when an unknown-kid refetch fails (token is invalid_token, not network)', async () => {
    const clock = useClock();
    const verify = createVerifier({ jwksUrl: server.url, issuer: ISSUER, cooldownMs: 1000 });
    expect((await verify(await sign(k1.privateKey, 'k1'))).sub).toBe('42');
    server.failWith(500);
    clock.advance(2000);
    const err = await rejection(verify(await sign(k2.privateKey, 'k2')));
    expect(err.code).toBe('invalid_token');
    expect(server.requests).toBe(2);
    expect((await verify(await sign(k1.privateKey, 'k1'))).sub).toBe('42');
    expect(server.requests).toBe(2);
    server.setKeys([await publicJwk(k1.publicKey, 'k1'), await publicJwk(k2.publicKey, 'k2')]);
    clock.advance(2000);
    expect((await verify(await sign(k2.privateKey, 'k2'))).sub).toBe('42');
  });

  it('still verifies a known kid after the cache went stale while the JWKS endpoint fails', async () => {
    const clock = useClock();
    const verify = createVerifier({ jwksUrl: server.url, issuer: ISSUER });
    expect((await verify(await sign(k1.privateKey, 'k1'))).sub).toBe('42');
    server.failWith(500);
    clock.advance(11 * 60_000); // past the 10 minute cacheMaxAgeMs
    expect((await verify(await sign(k1.privateKey, 'k1'))).sub).toBe('42');
    expect(server.requests).toBe(2); // the refresh was attempted and failed
  });

  it('refreshes after cacheMaxAgeMs and fails with network once maxStaleMs has passed', async () => {
    const clock = useClock();
    const verify = createVerifier({ jwksUrl: server.url, issuer: ISSUER, cacheMaxAgeMs: 1000, maxStaleMs: 60_000, cooldownMs: 100 });
    await verify(await sign(k1.privateKey, 'k1'));
    clock.advance(2000);
    await verify(await sign(k1.privateKey, 'k1'));
    expect(server.requests).toBe(2); // fresh refetch after the cache aged out
    server.failWith(500);
    clock.advance(30_000);
    expect((await verify(await sign(k1.privateKey, 'k1'))).sub).toBe('42'); // stale but within maxStaleMs
    clock.advance(40_000);
    const err = await rejection(verify(await sign(k1.privateKey, 'k1')));
    expect(err.code).toBe('network');
  });

  it('drops a retired key when a refetch succeeds', async () => {
    const clock = useClock();
    server.setKeys([await publicJwk(k1.publicKey, 'k1'), await publicJwk(k2.publicKey, 'k2')]);
    const verify = createVerifier({ jwksUrl: server.url, issuer: ISSUER });
    expect((await verify(await sign(k2.privateKey, 'k2'))).sub).toBe('42');
    server.setKeys([await publicJwk(k1.publicKey, 'k1')]);
    clock.advance(11 * 60_000);
    expect((await verify(await sign(k1.privateKey, 'k1'))).sub).toBe('42'); // stale refresh replaces the set
    const err = await rejection(verify(await sign(k2.privateKey, 'k2')));
    expect(err.code).toBe('invalid_token');
  });

  it('shares one in-flight fetch between concurrent verifies', async () => {
    const verify = createVerifier({ jwksUrl: server.url, issuer: ISSUER });
    const token = await sign(k1.privateKey, 'k1');
    const results = await Promise.all(Array.from({ length: 8 }, () => verify(token)));
    expect(results.every((c) => c.sub === '42')).toBe(true);
    expect(server.requests).toBe(1);
  });

  it('shares one failed fetch between concurrent verifies and retries on the next call', async () => {
    server.failWith(500);
    const verify = createVerifier({ jwksUrl: server.url, issuer: ISSUER });
    const token = await sign(k1.privateKey, 'k1');
    const errs = await Promise.all(Array.from({ length: 5 }, () => rejection(verify(token))));
    expect(errs.every((e) => e.code === 'network')).toBe(true);
    expect(server.requests).toBe(1);
    server.recover();
    expect((await verify(token)).sub).toBe('42');
  });

  it('accepts a token whose nbf is a few seconds ahead when clockToleranceSeconds allows it', async () => {
    const token = await sign(k1.privateKey, 'k1', {}, { nbf: now() + 5 });
    expect((await rejection(createVerifier({ jwksUrl: server.url, issuer: ISSUER })(token))).code).toBe('invalid_token');
    const tolerant = createVerifier({ jwksUrl: server.url, issuer: ISSUER, clockToleranceSeconds: 10 });
    expect((await tolerant(token)).sub).toBe('42');
  });

  it('accepts an audience array and matches any of its values', async () => {
    const verify = createVerifier({ jwksUrl: server.url, issuer: ISSUER, audience: ['api', 'web'] });
    expect((await verify(await sign(k1.privateKey, 'k1', {}, { aud: 'web' }))).sub).toBe('42');
    expect((await rejection(verify(await sign(k1.privateKey, 'k1', {}, { aud: 'other' })))).code).toBe('invalid_token');
  });

  it('reports a JWKS retrieval failure with no cached keys as network, not invalid_token', async () => {
    server.failWith(503);
    const verify = createVerifier({ jwksUrl: server.url, issuer: ISSUER });
    const err = await rejection(verify(await sign(k1.privateKey, 'k1')));
    expect(err.code).toBe('network');
    expect(err.status).toBe(0);
  });

  it('reports an unreachable JWKS host as network', async () => {
    const url = server.url;
    await server.close();
    const verify = createVerifier({ jwksUrl: url, issuer: ISSUER });
    const err = await rejection(verify(await sign(k1.privateKey, 'k1')));
    expect(err.code).toBe('network');
    server = await startJwksServer(); // keep afterEach happy
  });

  it('uses the injected fetch for the JWKS request', async () => {
    const seen: string[] = [];
    const verify = createVerifier({
      jwksUrl: server.url,
      issuer: ISSUER,
      fetch: (input, init) => {
        seen.push(String(input));
        return fetch(input, init);
      },
    });
    await verify(await sign(k1.privateKey, 'k1'));
    expect(seen).toEqual([server.url]);
  });

  it('never puts the token text in an error message', async () => {
    const verify = createVerifier({ jwksUrl: server.url, issuer: ISSUER });
    const tokens = [
      await sign(k2.privateKey, 'k1'),
      await sign(k1.privateKey, 'k1', {}, { exp: now() - 60 }),
      await sign(k1.privateKey, 'k1', {}, { iss: 'x' }),
      await sign(k1.privateKey, 'zz'),
      'not.a.jwt-secret-material',
    ];
    for (const t of tokens) {
      const err = await rejection(verify(t));
      for (const part of t.split('.')) if (part.length > 4) expect(err.message).not.toContain(part);
      expect(err.message).not.toContain(t);
    }
  });

  it('throws a TypeError for an invalid configuration', () => {
    expect(() => createVerifier({ jwksUrl: 'not a url', issuer: ISSUER })).toThrow(TypeError);
    expect(() => createVerifier({ jwksUrl: server.url, issuer: '' })).toThrow(TypeError);
    expect(() => createVerifier({ jwksUrl: server.url, issuer: ISSUER, maxStaleMs: -1 })).toThrow(TypeError);
  });
});
