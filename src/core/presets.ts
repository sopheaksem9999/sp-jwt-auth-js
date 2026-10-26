/** Deep-freezes a plain preset object so spreading it never lets a client mutate the shared value. */
function deepFreeze<T extends object>(o: T): Readonly<T> {
  for (const v of Object.values(o)) {
    if (typeof v === 'object' && v !== null && !Object.isFrozen(v)) deepFreeze(v);
  }
  return Object.freeze(o);
}

/**
 * Ready-made `endpoints` and `unwrap` for known hosts (spec §4.1 host table).
 * Spread one into `createJwtAuth` next to your own `baseUrl` and `mode`:
 *
 * ```ts
 * createJwtAuth({ baseUrl, ...presets.speedxSaas, mode: userSession({ storage }) });
 * ```
 *
 * Presets are frozen plain objects; they never include `baseUrl` or `mode`, and
 * `createJwtAuth` does not modify them. Override a single route by spreading
 * `endpoints` yourself: `endpoints: { ...presets.spJwtTest.endpoints, whoami: '/profile' }`.
 */
export const presets = deepFreeze({
  /** The sp-jwt-auth test host: `{ user, token: { … } }` login responses, no envelope. */
  spJwtTest: {
    endpoints: {
      login: '/auth/login',
      refresh: '/auth/refresh',
      logout: '/auth/logout',
      whoami: '/me',
    },
    unwrap: 'raw',
  },
  /** The SpeedX SaaS host: `{ success, data }` envelope, second factor, company switch and account routes. */
  speedxSaas: {
    endpoints: {
      login: '/auth/login',
      secondFactor: '/auth/login/2fa',
      refresh: '/auth/refresh',
      logout: '/auth/logout',
      whoami: '/auth/whoami',
      switchCompany: '/auth/impersonate_in',
      forgotPassword: '/auth/forgot-password',
      resetPassword: '/auth/reset-password',
      resendVerification: '/auth/resend-email-verification',
    },
    unwrap: 'sp-laravel-api',
  },
} as const);
