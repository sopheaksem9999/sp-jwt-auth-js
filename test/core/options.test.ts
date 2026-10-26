import { describe, expect, expectTypeOf, it } from 'vitest';
import { createJwtAuth, staticToken, userSession } from '../../src/index';
import type { Endpoints, JwtAuth, JwtAuthOptions, ModeContext } from '../../src/index';

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

describe('JwtAuthOptions.endpoints is optional', () => {
  it('types: createJwtAuth({ baseUrl, mode }) compiles without endpoints', () => {
    expectTypeOf<JwtAuthOptions['endpoints']>().toEqualTypeOf<Endpoints | undefined>();
    expectTypeOf(createJwtAuth({ baseUrl: 'https://api.example.com', mode: staticToken(() => 't') })).toEqualTypeOf<JwtAuth>();
    expectTypeOf(createJwtAuth({ baseUrl: 'https://api.example.com', mode: userSession() })).toEqualTypeOf<JwtAuth>();
    expectTypeOf(createJwtAuth({ baseUrl: 'https://api.example.com', endpoints: { whoami: '/me' }, mode: userSession() })).toEqualTypeOf<JwtAuth>();
    // Modes always see a resolved object.
    expectTypeOf<ModeContext['options']['endpoints']>().toEqualTypeOf<Endpoints>();
  });

  it('runtime: omitted means {} (package refresh route; host-only routes are not_configured)', async () => {
    const paths: string[] = [];
    const fetch = (async (input: string | URL) => {
      paths.push(new URL(String(input)).pathname);
      return json({ access_token: 'a2', refresh_token: 'r2', expires_in: 900, token_type: 'Bearer' });
    }) as typeof globalThis.fetch;
    const auth = createJwtAuth({ baseUrl: 'https://api.example.com', mode: userSession(), fetch });
    expect(auth.endpoint('refresh', 'refresh')).toBe('/auth/token/refresh');
    expect(() => auth.endpoint('whoami', 'core')).toThrow(expect.objectContaining({ code: 'not_configured' }));
    await expect(auth.login({})).rejects.toMatchObject({ code: 'not_configured' });
    await expect(auth.whoami()).rejects.toMatchObject({ code: 'not_configured' });
    await auth.logout(); // no session, no host logout: nothing to revoke, no request
    expect(paths).toEqual([]);

    const server = createJwtAuth({ baseUrl: 'https://api.example.com', mode: staticToken(() => 'tok') });
    expect(await server.getHeaders()).toEqual({ Authorization: 'Bearer tok' });
  });

  it('a provided endpoints object keeps its behaviour', () => {
    const auth = createJwtAuth({ baseUrl: 'https://api.example.com', endpoints: { refresh: '/auth/refresh', whoami: '/me' }, mode: userSession() });
    expect(auth.endpoint('refresh', 'refresh')).toBe('/auth/refresh');
    expect(auth.endpoint('whoami', 'core')).toBe('/me');
  });
});
