/**
 * Spec §4.5 rule → the deep tests that cover its edge cases: `file` (from the repo root) and exact `describe` /
 * `it` titles in that file. test/acceptance/refresh-rules-map.node.test.ts reads each file and fails when a title
 * is missing (renamed or deleted), so the map cannot rot. test/acceptance/refresh-rules.test.ts has one thin
 * public-API scenario per rule, titled with the same rule key.
 */
export interface DeepRef {
  file: string;
  titles: string[];
}

export const RULE_MAP: Record<string, DeepRef[]> = {
  'rule 1: proactive refresh': [
    {
      file: 'test/core/refresh.test.ts',
      titles: [
        'proactive refresh in getAccessToken',
        'does not refresh when exp - now >= refreshAheadSeconds',
        'honours a custom refreshAheadSeconds',
        'refreshes when exp is already in the past (clock skew / offline)',
        'falls back to the expires_in expiry for an opaque access token',
        'JWT exp wins over expires_in; exp 0 is not a real expiry',
      ],
    },
  ],
  'rule 2: single-flight in a process': [
    {
      file: 'test/core/refresh.test.ts',
      titles: [
        'createRefresher',
        'shares one in-flight promise between concurrent callers and clears it after a failure',
        '100 concurrent getAccessToken() calls within the ahead window make exactly one refresh request',
        'concurrent calls share one refresh',
        'getAccessToken and handleUnauthorized running together share one flight',
      ],
    },
  ],
  'rule 3: single-flight across tabs': [
    {
      file: 'test/core/crosstab.test.ts',
      titles: [
        'two instances sharing a store (two tabs)',
        'both at expiry: exactly one refresh request; the second re-reads the store inside the lock and adopts the pair',
        'after one instance logs out, the other becomes anonymous via the broadcast (no request)',
      ],
    },
    {
      file: 'test/core/cookie.test.ts',
      titles: [
        'cookie transport: tabs',
        "another tab's broadcast access token is used inside the lock when still fresh (one refresh in total)",
        'cookie transport: broadcast grace after a contended lock',
      ],
    },
  ],
  'rule 4: old access tokens die on rotation, retried once': [
    {
      file: 'test/core/refresh.test.ts',
      titles: [
        'handleUnauthorized with the failed request',
        'a 401 that arrives after the refresh completed retries with the new token without refreshing again',
      ],
    },
    {
      file: 'test/core/presets.test.ts',
      titles: ['retries once after a 401 using the refreshed token', 'does not retry twice and rejects with the 401 when the session is gone'],
    },
  ],
  'rule 5: refresh failure semantics': [
    {
      file: 'test/core/refresh.test.ts',
      titles: [
        'refresh failure',
        'refresh 401 ends the session: store cleared (deviceId kept), anonymous, session_ended, handleUnauthorized false',
        'a network error keeps the tokens and state; handleUnauthorized rejects with network (status 0)',
        'refresh 503 keeps the tokens and state; handleUnauthorized rejects with the 503 error',
      ],
    },
  ],
  'rule 6: clientCredentials': [
    {
      file: 'test/core/modes.test.ts',
      titles: [
        'clientCredentials',
        'expires_in: 0 falls back to defaultTtlSeconds (J1)',
        're-fetches refreshAheadSeconds before expiry',
        '50 concurrent getAccessToken calls share one token request',
        'concurrent 401s share one re-fetch',
      ],
    },
  ],
};
