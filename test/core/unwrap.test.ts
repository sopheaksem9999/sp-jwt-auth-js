import { describe, expect, it } from 'vitest';
import { detectChallenge, findTokenPair, unwrap } from '../../src/core/unwrap';

const pair = { access_token: 'a', refresh_token: 'r', expires_in: 60, token_type: 'Bearer' };

describe('unwrap', () => {
  it('raw returns the body', () => {
    const b = { data: 1 };
    expect(unwrap('raw', b)).toBe(b);
  });
  it('laravel unwraps { data }', () => {
    expect(unwrap('laravel', { data: { x: 1 } })).toEqual({ x: 1 });
    expect(unwrap('laravel', { x: 1 })).toEqual({ x: 1 });
  });
  it('sp-laravel-api unwraps the envelope', () => {
    expect(unwrap('sp-laravel-api', { success: true, error_code: 0, data: { x: 1 }, meta: {} })).toEqual({ x: 1 });
    expect(unwrap('sp-laravel-api', { x: 1 })).toEqual({ x: 1 });
  });
  it('function mode is applied', () => {
    expect(unwrap((b) => (b as { n: number }).n + 1, { n: 1 })).toBe(2);
  });
});

describe('findTokenPair', () => {
  it('finds a top-level pair', () => expect(findTokenPair(pair)).toEqual(pair));
  it('finds a pair in .token', () => expect(findTokenPair({ token: pair })).toEqual(pair));
  it('finds a pair in an envelope .data', () => expect(findTokenPair({ success: true, data: pair })).toEqual(pair));
  it('returns null otherwise', () => {
    expect(findTokenPair({ foo: 1 })).toBeNull();
    expect(findTokenPair(null)).toBeNull();
    expect(findTokenPair('x')).toBeNull();
  });
});

describe('detectChallenge', () => {
  it('detects requires_2fa', () => {
    expect(detectChallenge({ requires_2fa: true, '2fa_token': 't' })).toEqual({ kind: '2fa_token', token: 't' });
  });
  it('detects challenge_id', () => {
    expect(detectChallenge({ challenge_id: 'c' })).toEqual({ kind: 'challenge_id', token: 'c' });
  });
  it('an unwrapped envelope is not a challenge', () => {
    expect(detectChallenge({ success: true, data: { requires_2fa: true, '2fa_token': 't' } })).toBeNull();
  });
  it('returns null for other bodies', () => {
    expect(detectChallenge(pair)).toBeNull();
    expect(detectChallenge(null)).toBeNull();
  });
});

describe('findTokenPair leniency (J3)', () => {
  const at = { access_token: 'a', refresh_token: 'r' };
  it('parses the sp-laravel-api envelope with an expiry', () => {
    const body = unwrap('sp-laravel-api', { success: true, data: { ...at, expires_in: 900 } });
    expect(findTokenPair(body)?.expires_in).toBe(900);
  });
  it('parses a flat body', () => expect(findTokenPair({ ...at, expires_in: 900 })?.expires_in).toBe(900));
  it('a missing expires_in becomes 0', () => expect(findTokenPair(at)?.expires_in).toBe(0));
  it('parses a numeric string', () => expect(findTokenPair({ ...at, expires_in: '900' })?.expires_in).toBe(900));
  it.each([-5, 'abc', Number.NaN, Number.POSITIVE_INFINITY, null, '', '-5'])('%s becomes 0', (v) => {
    expect(findTokenPair({ ...at, expires_in: v })?.expires_in).toBe(0);
  });
  it('an empty or missing access_token is not a pair', () => {
    expect(findTokenPair({ access_token: '', expires_in: 900 })).toBeNull();
    expect(findTokenPair({ expires_in: 900 })).toBeNull();
  });
});
