import { SpAuthError } from '../core/errors';

const MODULE = 'oauth';

/** RFC 7636 §4.1 unreserved characters: `A-Z a-z 0-9 - . _ ~` (66 of them). */
const UNRESERVED = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';

function webCrypto(): Crypto {
  const c = (globalThis as { crypto?: Crypto }).crypto;
  if (!c || typeof c.getRandomValues !== 'function') {
    throw new SpAuthError({ status: 0, code: 'not_configured', message: 'Web Crypto is not available in this runtime', module: MODULE });
  }
  return c;
}

/** Base64url (RFC 4648 §5) of `bytes`, without padding. */
export function base64url(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** `byteLength` random bytes from `crypto.getRandomValues`, base64url encoded (no padding). */
export function randomBase64url(byteLength: number): string {
  return base64url(webCrypto().getRandomValues(new Uint8Array(byteLength)));
}

/**
 * PKCE `code_challenge` for the `S256` method (RFC 7636 §4.2):
 * `base64url(SHA-256(verifier))` without padding, computed with Web Crypto
 * (`crypto.subtle`, which browsers expose on HTTPS and localhost only).
 * Rejects `SpAuthError('not_configured')` when `crypto.subtle` is unavailable.
 */
export async function pkceChallenge(verifier: string): Promise<string> {
  const subtle = (globalThis as { crypto?: Crypto }).crypto?.subtle;
  if (!subtle) {
    throw new SpAuthError({
      status: 0,
      code: 'not_configured',
      message: 'crypto.subtle is not available (a secure context is required)',
      module: MODULE,
    });
  }
  const digest = await subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  return base64url(new Uint8Array(digest));
}

/**
 * Generates a PKCE `code_verifier` (RFC 7636 §4.1): `length` characters (43 to
 * 128, default 64) from the unreserved set, drawn with `crypto.getRandomValues`
 * and rejection sampling, so no character is more likely than another (no
 * modulo bias). Throws `RangeError` for a length outside 43..128.
 */
export function generateCodeVerifier(length = 64): string {
  if (!Number.isInteger(length) || length < 43 || length > 128) {
    throw new RangeError('code verifier length must be an integer from 43 to 128');
  }
  const crypto = webCrypto();
  const n = UNRESERVED.length;
  // Largest multiple of n that fits in a byte: bytes at or above it are discarded.
  const limit = 256 - (256 % n);
  let out = '';
  while (out.length < length) {
    const buf = crypto.getRandomValues(new Uint8Array(length * 2));
    for (const b of buf) {
      if (b < limit && out.length < length) out += UNRESERVED[b % n];
    }
  }
  return out;
}
