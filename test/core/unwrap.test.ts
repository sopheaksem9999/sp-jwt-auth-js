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
