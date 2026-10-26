import { decodeClaims } from './claims';
import type { Claims } from './claims';

/** Snapshot of the session, safe to hand to `useSyncExternalStore` (same reference until something changes). */
export interface AuthState {
  /** `unknown` until storage has been read (or, for cookie transport, `restore()` resolved). */
  status: 'unknown' | 'authenticated' | 'anonymous';
  /** Host user object; stays `null` until `whoami` fills it. */
  user: unknown | null;
  /** Decoded (unverified) access-token claims, `null` when anonymous or the token is opaque. */
  claims: Claims | null;
  /** Company id read from the configured company claim, stringified. */
  companyId: string | null;
  /** `true` when the access token carries a truthy `impersonated` claim. */
  impersonated: boolean;
}

/** Initial state before anything has been read. */
export const UNKNOWN_STATE: AuthState = Object.freeze({
  status: 'unknown',
  user: null,
  claims: null,
  companyId: null,
  impersonated: false,
}) as AuthState;

/** Anonymous state with every field cleared. */
export const ANONYMOUS_STATE: AuthState = Object.freeze({
  status: 'anonymous',
  user: null,
  claims: null,
  companyId: null,
  impersonated: false,
}) as AuthState;

function truthyFlag(v: unknown): boolean {
  return v === true || v === 1 || v === '1' || v === 'true';
}

/**
 * Builds the authenticated state for an access token. `previousUser` is kept
 * only when the token's subject is unchanged (a rotation, not a new login).
 */
export function authenticatedState(accessToken: string, companyClaim: string, previous: AuthState): AuthState {
  const claims = decodeClaims(accessToken);
  const raw = claims?.[companyClaim];
  const companyId = raw === undefined || raw === null || raw === '' ? null : String(raw);
  const sameSubject = previous.status === 'authenticated' && previous.claims?.sub === claims?.sub;
  return {
    status: 'authenticated',
    user: sameSubject ? previous.user : null,
    claims,
    companyId,
    impersonated: truthyFlag(claims?.impersonated),
  };
}

function shallowEqual(a: AuthState, b: AuthState): boolean {
  return (
    a.status === b.status &&
    a.user === b.user &&
    a.companyId === b.companyId &&
    a.impersonated === b.impersonated &&
    JSON.stringify(a.claims) === JSON.stringify(b.claims)
  );
}

/** Observable holder for `AuthState`; listener errors are swallowed so one bad listener cannot break the others. */
export interface StateContainer {
  get(): AuthState;
  /** Replaces the state; keeps the old reference (and notifies nobody) when nothing changed. */
  set(next: AuthState): void;
  subscribe(listener: () => void): () => void;
}

/** Creates a `StateContainer` starting at `UNKNOWN_STATE`. */
export function createState(): StateContainer {
  let current = UNKNOWN_STATE;
  const listeners = new Set<() => void>();
  return {
    get: () => current,
    set(next) {
      if (shallowEqual(current, next)) return;
      current = next;
      for (const l of [...listeners]) {
        try {
          l();
        } catch {
          /* a listener must not break the others */
        }
      }
    },
    subscribe(listener) {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
  };
}
