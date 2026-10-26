import pkg from '../package.json';

/** Package version, inlined from package.json at build time. */
export const VERSION: string = pkg.version;

export { SpAuthError, authErrorFromResponse, isSpAuthError } from './core/errors';
export type { AuthErrorContext, SpAuthErrorCode, SpAuthErrorInit } from './core/errors';
export { detectChallenge, findTokenPair, unwrap } from './core/unwrap';
export type { TokenPairRaw, Unwrap } from './core/unwrap';
export { decodeClaims } from './core/claims';
export type { Claims } from './core/claims';
