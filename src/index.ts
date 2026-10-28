import pkg from '../package.json';

/** Package version, inlined from package.json at build time. */
export const VERSION: string = pkg.version;

export { SpAuthError, authErrorFromResponse, isSpAuthError } from './core/errors';
export type { AuthErrorContext, SpAuthErrorCode, SpAuthErrorInit } from './core/errors';
export { detectChallenge, findTokenPair, unwrap } from './core/unwrap';
export type { TokenPairRaw, Unwrap } from './core/unwrap';
export type { AuthLogCall, AuthLogEntry, AuthRequestLogger } from './core/log-types';
export { decodeClaims } from './core/claims';
export type { Claims } from './core/claims';
export { ensureDeviceId, keyValueTokenStore, memoryStore, webStorageStore } from './core/stores';
export type { KeyValueStorage, StorageKeys, TokenStore, Tokens } from './core/stores';
export { createCrossTab } from './core/crosstab';
export type { BroadcastToken, CrossTab, CrossTabDeps, LockManagerLike, TabMessage } from './core/crosstab';
export { readCookie } from './core/cookie';
export { presets } from './core/presets';
export { createJwtAuth, userSession } from './core/create-jwt-auth';
export { apiKey, clientCredentials, staticToken } from './core/modes';
export type { ClientCredentialsOptions } from './core/modes';
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
  SessionEndReason,
  SessionEndedEvent,
  UnauthorizedContext,
  UserSessionOptions,
} from './core/create-jwt-auth';
