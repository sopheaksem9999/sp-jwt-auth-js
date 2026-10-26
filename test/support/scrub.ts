// Removes credentials from recorded exchanges before anything is written to disk.
// Copied into each package on purpose: packages never import from each other.
import type { RecordedEntry } from './replay';

/** Replaces every secret value (rule applied uniformly: JSON keys, form params, query strings, headers). */
export const SCRUBBED = '[scrubbed]';

/** Key names (case-insensitive) whose values are secret, in JSON bodies, form params and query strings. */
export const SECRET_KEYS: ReadonlySet<string> = new Set([
  'password',
  'password_confirmation',
  '2fa_token',
  'otp',
  'code',
  'token',
  'id_token',
  'api_key',
  'apikey',
  'csrf',
  '_token',
  'state',
  'client_secret',
  'secret',
  'access_token',
  'refresh_token',
]);

/** Header names (lower case) whose values are secret. */
export const SECRET_HEADERS: ReadonlySet<string> = new Set([
  'authorization',
  'proxy-authorization',
  'cookie',
  'set-cookie',
  'x-sp-csrf',
  'x-csrf-token',
  'x-xsrf-token',
]);

/** The only request headers ever written to a fixture. */
export const REQUEST_HEADER_ALLOWLIST: ReadonlySet<string> = new Set(['accept', 'content-type']);

export const isSecretKey = (k: string): boolean => SECRET_KEYS.has(k.toLowerCase());

/** Code-unit comparison (locale independent). */
export const cmp = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

/** Recursively replaces secret values; the result is a copy. */
export function scrubValue(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(scrubValue);
  if (typeof v === 'object' && v !== null) {
    const out: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(v)) out[k] = isSecretKey(k) ? SCRUBBED : scrubValue(x);
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
  const i = value.indexOf('?');
  if (i < 0) return value;
  const hash = value.indexOf('#', i);
  const end = hash < 0 ? value.length : hash;
  const qs = scrubParams(value.slice(i + 1, end), false);
  return `${value.slice(0, i)}${qs === '' ? '' : `?${qs}`}${value.slice(end)}`;
}

function scrubBody(body: unknown): unknown {
  if (typeof body === 'string') {
    try {
      const parsed: unknown = JSON.parse(body);
      if (typeof parsed === 'object' && parsed !== null) return JSON.stringify(scrubValue(parsed));
    } catch {
      /* not JSON: leave as is */
    }
    return body;
  }
  return scrubValue(body);
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
 * allowlist; query secrets, response JSON secrets, secret headers and `Location` query secrets are replaced.
 */
export function scrub(entry: RecordedEntry): RecordedEntry {
  const r = entry.request;
  const request: RecordedEntry['request'] = { method: r.method, path: r.path, query: scrubQuery(r.query) };
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
