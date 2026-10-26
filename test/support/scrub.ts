// Removes credentials from a recorded entry before it is written to disk.
// Copied into each package on purpose: packages never import from each other.
import type { RecordedEntry } from './replay';

const SECRET_KEYS: ReadonlySet<string> = new Set(['access_token', 'refresh_token', 'secret', 'client_secret']);
const SECRET_HEADERS: ReadonlySet<string> = new Set(['authorization', 'proxy-authorization', 'cookie', 'set-cookie']);

function scrubValue(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(scrubValue);
  if (typeof v === 'object' && v !== null) {
    const out: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(v)) {
      if (!SECRET_KEYS.has(k.toLowerCase())) out[k] = scrubValue(x);
    }
    return out;
  }
  return v;
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

function scrubHeaders(h: Record<string, string> | undefined): Record<string, string> | undefined {
  if (h === undefined) return undefined;
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(h)) if (!SECRET_HEADERS.has(k.toLowerCase())) out[k] = v;
  return out;
}

/** Returns a copy of `entry` without tokens, secrets, Authorization, Cookie or Set-Cookie. */
export function scrub(entry: RecordedEntry): RecordedEntry {
  const request: RecordedEntry['request'] = { ...entry.request };
  const reqHeaders = scrubHeaders(entry.request.headers);
  if (reqHeaders !== undefined) request.headers = reqHeaders;
  if (entry.request.body !== undefined) request.body = scrubBody(entry.request.body);
  return {
    request,
    response: {
      ...entry.response,
      headers: scrubHeaders(entry.response.headers) ?? {},
      body: scrubBody(entry.response.body),
    },
  };
}
