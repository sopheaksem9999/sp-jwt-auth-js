import { describe, expect, it, vi } from 'vitest';
import { generateCodeVerifier, pkceChallenge } from '../../src/oauth';

describe('pkceChallenge', () => {
  it('matches the RFC 7636 appendix B vector', async () => {
    expect(await pkceChallenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')).toBe(
      'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
    );
  });

  it('is base64url without padding', async () => {
    const c = await pkceChallenge('x');
    expect(c).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });
});

describe('generateCodeVerifier', () => {
  it('defaults to a 64 character verifier from the RFC 7636 unreserved set', () => {
    const v = generateCodeVerifier();
    expect(v).toHaveLength(64);
    expect(v).toMatch(/^[A-Za-z0-9\-._~]+$/);
  });

  it('honours 43 and 128, and rejects lengths outside 43..128', () => {
    expect(generateCodeVerifier(43)).toHaveLength(43);
    expect(generateCodeVerifier(128)).toHaveLength(128);
    expect(() => generateCodeVerifier(42)).toThrow(RangeError);
    expect(() => generateCodeVerifier(129)).toThrow(RangeError);
    expect(() => generateCodeVerifier(50.5)).toThrow(RangeError);
  });

  it('is random and uses the whole alphabet without bias toward the start', () => {
    const seen = new Map<string, number>();
    let total = 0;
    for (let i = 0; i < 200; i++) {
      for (const ch of generateCodeVerifier(128)) {
        seen.set(ch, (seen.get(ch) ?? 0) + 1);
        total++;
      }
    }
    expect(seen.size).toBe(66);
    // Expected 1/66 each (~388 of 25600); a modulo-biased sampler would put some characters near double.
    for (const n of seen.values()) expect(n / total).toBeLessThan(0.025);
    expect(generateCodeVerifier()).not.toBe(generateCodeVerifier());
  });

  it('discards bytes at or above 198 (the largest multiple of 66 in a byte) instead of folding them with modulo', () => {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
    // Even positions are rejected bytes (>= 198), odd positions are accepted bytes 0, 1, 2, ...
    const spy = vi.spyOn(globalThis.crypto, 'getRandomValues').mockImplementation(((buf: Uint8Array) => {
      for (let i = 0; i < buf.length; i++) buf[i] = i % 2 === 0 ? 198 + (i % 58) : (i >> 1) % 198;
      return buf;
    }) as typeof globalThis.crypto.getRandomValues);
    try {
      const v = generateCodeVerifier(128);
      const expected = Array.from({ length: 128 }, (_, k) => alphabet[k % 198 % 66]).join('');
      expect(v).toBe(expected);
    } finally {
      spy.mockRestore();
    }
  });
});
