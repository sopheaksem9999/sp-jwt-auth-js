import { describe, expect, it } from 'vitest';
import { decodeClaims } from '../../src/core/claims';

function b64url(s: string): string {
  const bytes = new TextEncoder().encode(s);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
const jwt = (payload: unknown): string =>
  `${b64url('{"alg":"none"}')}.${b64url(JSON.stringify(payload))}.sig`;

describe('decodeClaims', () => {
  it('decodes claims including unicode', () => {
    const c = decodeClaims(jwt({ sub: 42, exp: 100, iat: 1, sid: 's', scopes: ['a', 'b'], name: 'សុភ័ក្ត្រ ✓' }));
    expect(c).not.toBeNull();
    expect(c?.sub).toBe('42');
    expect(c?.scopes).toEqual(['a', 'b']);
    expect(c?.name).toBe('សុភ័ក្ត្រ ✓');
    expect(c?.exp).toBe(100);
  });
  it('normalises scopes from a space-separated string and defaults to []', () => {
    expect(decodeClaims(jwt({ sub: 'x', exp: 1, scopes: 'a b' }))?.scopes).toEqual(['a', 'b']);
    expect(decodeClaims(jwt({ sub: 'x', exp: 1 }))?.scopes).toEqual([]);
  });
  it('returns null for non-JWTs', () => {
    expect(decodeClaims('spoat_abc.def')).toBeNull();
    expect(decodeClaims('spak_abcdef123')).toBeNull();
    expect(decodeClaims('garbage')).toBeNull();
    expect(decodeClaims('a.b.c')).toBeNull();
    expect(decodeClaims('')).toBeNull();
  });
  it('returns null when the payload is not an object', () => {
    expect(decodeClaims(`${b64url('{}')}.${b64url('[1]')}.s`)).toBeNull();
  });
});
