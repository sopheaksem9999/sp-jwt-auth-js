// Removes credentials from recorded exchanges before anything is written to disk.
// Copied into each package on purpose: packages never import from each other.
import type { RecordedEntry } from './replay';

/** Replaces every secret value (rule applied uniformly: JSON keys, form params, query strings, headers). */
export const SCRUBBED = '[scrubbed]';

/** Normal form used to match key names: lower case with `-` and `_` removed (`accessToken`, `access-token`, `ACCESS_TOKEN` all become `accesstoken`). */
export const normaliseKey = (k: string): string => k.toLowerCase().replace(/[-_]/g, '');

/** Secret key names (normalised, see `normaliseKey`) scrubbed on BOTH the request and the response side. */
export const SECRET_KEYS: ReadonlySet<string> = new Set([
  'password',
  'passwordconfirmation',
  '2fatoken',
  'idtoken',
  'apikey',
  'csrf',
  'csrftoken',
  'xsrftoken',
  'clientsecret',
  'secret',
  'accesstoken',
  'refreshtoken',
]);

/**
 * Normalised key names scrubbed ONLY on the request side (query, form, JSON and FormData request fields, and
 * `Location` URLs). Response bodies keep them, so error/business fields such as `code` and `state` stay faithful.
 */
export const REQUEST_ONLY_SECRET_KEYS: ReadonlySet<string> = new Set(['code', 'state', 'token', 'otp']);

export type Side = 'request' | 'response';

/** Header names (lower case) whose values are secret. */
export const SECRET_HEADERS: ReadonlySet<string> = new Set([
  'authorization',
  'proxy-authorization',
  'cookie',
  'set-cookie',
  'x-sp-csrf',
  'x-csrf-token',
  'x-xsrf-token',
  'x-auth-token',
  'x-api-key',
  'x-refresh-token',
]);

/** The only request headers ever written to a fixture. */
export const REQUEST_HEADER_ALLOWLIST: ReadonlySet<string> = new Set(['accept', 'content-type']);

export function isSecretKey(k: string, side: Side = 'request'): boolean {
  const n = normaliseKey(k);
  return SECRET_KEYS.has(n) || (side === 'request' && REQUEST_ONLY_SECRET_KEYS.has(n));
}

/**
 * Scrubs the token/hash segment of the known sensitive route shapes `/password/reset/<token>` and
 * `/email/verify/<id>/<hash>` (the id stays); applies to request paths and to `Location` paths. Idempotent.
 */
export function scrubPath(path: string): string {
  return path
    .replace(/(^|\/)(password\/reset)\/[^/?#]+/g, `$1$2/${SCRUBBED}`)
    .replace(/(^|\/)(email\/verify\/[^/?#]+)\/[^/?#]+/g, `$1$2/${SCRUBBED}`);
}

/** Code-unit comparison (locale independent). */
export const cmp = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

/** Recursively replaces secret values; the result is a copy. */
export function scrubValue(v: unknown, side: Side = 'request'): unknown {
  if (Array.isArray(v)) return v.map((x) => scrubValue(x, side));
  if (typeof v === 'object' && v !== null) {
    const out: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(v)) {
      // A response `token` field holding a string is an opaque credential; an object `token` (`{ token: { access_token } }`) is recursed into.
      const secretString = side === 'response' && normaliseKey(k) === 'token' && typeof x === 'string';
      out[k] = isSecretKey(k, side) || secretString ? SCRUBBED : scrubValue(x, side);
    }
    return out;
  }
  return v;
}

/** Recursively sorts object keys (code-unit order). */
export function sortKeys(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (typeof v === 'object' && v !== null) {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(v).sort(cmp)) out[k] = sortKeys((v as Record<string, unknown>)[k]);
    return out;
  }
  return v;
}

/** Scrubs secret params of a query/form string; `sort` orders the pairs by key then value. */
export function scrubParams(search: string, sort: boolean): string {
  const pairs: [string, string][] = [];
  new URLSearchParams(search).forEach((v, k) => pairs.push([k, isSecretKey(k) ? SCRUBBED : v]));
  if (sort) pairs.sort(([a, av], [b, bv]) => cmp(a, b) || cmp(av, bv));
  return new URLSearchParams(pairs).toString();
}

/** Scrubbed, sorted query string (no leading `?`). Idempotent. */
export const scrubQuery = (search: string): string => scrubParams(search, true);

function scrubLocation(value: string): string {
  const h = value.indexOf('#');
  const fragment = h < 0 ? '' : value.slice(h + 1);
  const beforeHash = h < 0 ? value : value.slice(0, h);
  const q = beforeHash.indexOf('?');
  const path = scrubPath(q < 0 ? beforeHash : beforeHash.slice(0, q));
  const qs = q < 0 ? '' : scrubParams(beforeHash.slice(q + 1), false);
  // A fragment is only parsed as params when it looks like `a=b`; a route fragment such as `#/inbox` is kept.
  const frag = h < 0 ? '' : `#${fragment.includes('=') ? scrubParams(fragment, false) : fragment}`;
  return `${path}${q < 0 ? '' : qs === '' ? '' : `?${qs}`}${frag}`;
}

function scrubBody(body: unknown): unknown {
  if (typeof body === 'string') {
    try {
      const parsed: unknown = JSON.parse(body);
      if (typeof parsed === 'object' && parsed !== null) return JSON.stringify(scrubValue(parsed, 'response'));
    } catch {
      /* not JSON: leave as is */
    }
    return body;
  }
  return scrubValue(body, 'response');
}

function scrubResponseHeaders(h: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(h)) {
    const l = k.toLowerCase();
    out[k] = SECRET_HEADERS.has(l) ? SCRUBBED : l === 'location' ? scrubLocation(v) : v;
  }
  return out;
}

/**
 * Returns a scrubbed copy of `entry`. Request bodies are never kept; request headers are reduced to the
 * allowlist; query secrets, response JSON secrets, secret headers and `Location` query/fragment secrets are replaced,
 * and so are the token/hash segments of the known sensitive paths (`scrubPath`).
 */
export function scrub(entry: RecordedEntry): RecordedEntry {
  const r = entry.request;
  const request: RecordedEntry['request'] = { method: r.method, path: scrubPath(r.path), query: scrubQuery(r.query) };
  if (r.bodyHash !== undefined) request.bodyHash = r.bodyHash;
  if (r.headers !== undefined) {
    const h: Record<string, string> = {};
    for (const [k, v] of Object.entries(r.headers)) if (REQUEST_HEADER_ALLOWLIST.has(k.toLowerCase())) h[k] = v;
    request.headers = h;
  }
  return {
    request,
    response: { ...entry.response, headers: scrubResponseHeaders(entry.response.headers), body: scrubBody(entry.response.body) },
  };
}
