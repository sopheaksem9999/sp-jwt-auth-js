import { describe, expect, it } from 'vitest';
import { resolveUrl } from '../../src/core/http';

describe('resolveUrl', () => {
  it('keeps the base path for a leading-slash endpoint', () => {
    expect(resolveUrl('https://api.example.com/v1', '/auth/login')).toBe('https://api.example.com/v1/auth/login');
  });
  it('handles a trailing-slash base without doubling slashes', () => {
    expect(resolveUrl('https://api.example.com/v1/', '/auth/login')).toBe('https://api.example.com/v1/auth/login');
    expect(resolveUrl('https://api.example.com//', 'auth/login')).toBe('https://api.example.com/auth/login');
  });
  it('adds the slash for an endpoint without one', () => {
    expect(resolveUrl('https://api.example.com/v1', 'auth/login')).toBe('https://api.example.com/v1/auth/login');
  });
  it('treats a colon in the first segment as plain concatenation', () => {
    expect(resolveUrl('https://api.example.com/v1', '/a:b/c')).toBe('https://api.example.com/v1/a:b/c');
    expect(resolveUrl('https://api.example.com/v1', 'a:b/c')).toBe('https://api.example.com/v1/a:b/c');
  });
  it('passes an absolute https endpoint through', () => {
    expect(resolveUrl('https://api.example.com/v1', 'https://other.example.com/x')).toBe('https://other.example.com/x');
  });
});
