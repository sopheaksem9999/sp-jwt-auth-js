import pkg from '../package.json';

/** Package version, inlined from package.json at build time. */
export const VERSION: string = pkg.version;

export { SpAuthError, authErrorFromResponse, isSpAuthError } from './core/errors';
export type { AuthErrorContext, SpAuthErrorCode, SpAuthErrorInit } from './core/errors';
export { detectChallenge, findTokenPair, unwrap } from './core/unwrap';
export type { TokenPairRaw, Unwrap } from './core/unwrap';
export { decodeClaims } from './core/claims';
export type { Claims } from './core/claims';
export { ensureDeviceId, memoryStore, webStorageStore } from './core/stores';
export type { TokenStore, Tokens } from './core/stores';
export { createJwtAuth, userSession } from './core/create-jwt-auth';
export type {
  AuthEvent,
  AuthMode,
  AuthState,
  Challenge,
  Endpoints,
  HttpRequest,
  HttpResult,
  JwtAuth,
  JwtAuthOptions,
  LoginResult,
  ModeContext,
  ModeRuntime,
  UnauthorizedContext,
  UserSessionOptions,
} from './core/create-jwt-auth';
