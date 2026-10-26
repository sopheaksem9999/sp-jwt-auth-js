// Contract-test helpers: replay recorded HTTP exchanges, or hit a live backend (optionally recording).
// Copied into each package on purpose: packages never import from each other.
// Node-only (node:fs, node:crypto); runs in the vitest `node` project only.
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { scrub } from './scrub';

/** One recorded exchange. Stored as one JSON file per request, named `<entryKey>.json`. */
export interface RecordedEntry {
  request: {
    method: string;
    /** URL path without host. */
    path: string;
    /** Query string with pairs sorted, e.g. `a=1&b=2` (no leading `?`). */
    query: string;
    /** sha256 (hex) of the raw request body; absent when there is none. Computed before scrubbing. */
    bodyHash?: string;
    headers?: Record<string, string>;
    body?: unknown;
  };
  response: {
    status: number;
    headers: Record<string, string>;
    /** Parsed JSON when the response was JSON, otherwise the text. */
    body: unknown;
  };
}

export function hashBody(body: string): string {
  return createHash('sha256').update(body).digest('hex');
}

function sortedQuery(search: string): string {
  const pairs = [...new URLSearchParams(search)].sort(([a, av], [b, bv]) => (a === b ? av.localeCompare(bv) : a.localeCompare(b)));
  return new URLSearchParams(pairs).toString();
}

/** Stable key: sha256 of method, path, sorted query and body hash (first 24 hex chars). */
export function entryKey(r: Pick<RecordedEntry['request'], 'method' | 'path' | 'query' | 'bodyHash'>): string {
  return createHash('sha256')
    .update([r.method.toUpperCase(), r.path, sortedQuery(r.query), r.bodyHash ?? ''].join('\n'))
    .digest('hex')
    .slice(0, 24);
}

async function describeRequest(
  input: Parameters<typeof fetch>[0],
  init: RequestInit | undefined,
): Promise<{ url: string; method: string; request: RecordedEntry['request']; rawBody: string }> {
  const req = input instanceof Request ? input : undefined;
  const url = req?.url ?? String(input);
  const method = (init?.method ?? req?.method ?? 'GET').toUpperCase();
  let rawBody = '';
  const b = init?.body;
  if (typeof b === 'string') rawBody = b;
  else if (b instanceof URLSearchParams) rawBody = b.toString();
  else if (b !== undefined && b !== null) rawBody = await new Response(b).text();
  else if (req !== undefined && req.body !== null) rawBody = await req.clone().text();
  const u = new URL(url);
  const headers: Record<string, string> = {};
  new Headers(init?.headers ?? req?.headers).forEach((v, k) => {
    headers[k] = v;
  });
  const request: RecordedEntry['request'] = { method, path: u.pathname, query: sortedQuery(u.search), headers };
  if (rawBody !== '') {
    request.bodyHash = hashBody(rawBody);
    try {
      request.body = JSON.parse(rawBody);
    } catch {
      request.body = rawBody;
    }
  }
  return { url, method, request, rawBody };
}

function loadDir(dir: string): Map<string, RecordedEntry> {
  const map = new Map<string, RecordedEntry>();
  if (!existsSync(dir)) return map;
  for (const f of readdirSync(dir).filter((n) => n.endsWith('.json')).sort()) {
    map.set(f.slice(0, -5), JSON.parse(readFileSync(join(dir, f), 'utf8')) as RecordedEntry);
  }
  return map;
}

/** A fetch that answers from recorded entries in `dir`; throws on an unrecorded request. */
export function replayFetch(dir: string): typeof fetch {
  return async (input, init) => {
    const { url, method, request } = await describeRequest(input, init);
    const hit = loadDir(dir).get(entryKey(request));
    if (hit === undefined) throw new Error(`replayFetch: unrecorded request ${method} ${url} (fixtures: ${dir})`);
    const { status, headers, body } = hit.response;
    const text = body === undefined || body === null ? null : typeof body === 'string' ? body : JSON.stringify(body);
    return new Response(status === 204 || status === 304 ? null : text, { status, headers });
  };
}

const DROP_RESPONSE_HEADERS: ReadonlySet<string> = new Set(['content-encoding', 'content-length', 'transfer-encoding']);

function recordingFetch(live: typeof fetch, dir: string): typeof fetch {
  return async (input, init) => {
    const { request } = await describeRequest(input, init);
    const res = await live(input, init);
    const text = await res.clone().text();
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => {
      if (!DROP_RESPONSE_HEADERS.has(k)) headers[k] = v;
    });
    let body: unknown = text;
    try {
      body = text === '' ? '' : JSON.parse(text);
    } catch {
      /* keep text */
    }
    const entry = scrub({ request, response: { status: res.status, headers, body } });
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, `${entryKey(request)}.json`), `${JSON.stringify(entry, null, 2)}\n`);
    return res;
  };
}

export interface LiveOrReplayOptions {
  env?: Record<string, string | undefined>;
  /** Defaults to `<cwd>/test/fixtures`. */
  fixturesRoot?: string;
  /** Defaults to `globalThis.fetch`. */
  liveFetch?: typeof fetch;
}

export interface LiveOrReplay {
  fetch: typeof fetch;
  mode: 'live' | 'replay';
  baseUrl: string;
  /** True when replay mode has at least one recorded entry. */
  hasFixtures: boolean;
}

/**
 * Live when `SP_CONTRACT_URL` is set (with `SP_CONTRACT_RECORD=1` also writing scrubbed entries to
 * `test/fixtures/<SP_CONTRACT_BACKEND_VERSION>/`); otherwise replays the recorded fixtures.
 */
export function liveOrReplay(opts: LiveOrReplayOptions = {}): LiveOrReplay {
  const env = opts.env ?? process.env;
  const root = opts.fixturesRoot ?? join(process.cwd(), 'test', 'fixtures');
  const version = env.SP_CONTRACT_BACKEND_VERSION;
  const url = env.SP_CONTRACT_URL;

  if (url !== undefined && url !== '') {
    const live = opts.liveFetch ?? globalThis.fetch.bind(globalThis);
    const record = env.SP_CONTRACT_RECORD === '1';
    const f = record ? recordingFetch(live, join(root, version ?? 'unversioned')) : live;
    return { fetch: f, mode: 'live', baseUrl: url.replace(/\/+$/, ''), hasFixtures: false };
  }

  const versions = existsSync(root)
    ? readdirSync(root, { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => d.name).sort()
    : [];
  const chosen = version ?? versions[versions.length - 1];
  const dir = join(root, chosen ?? '');
  const hasFixtures = chosen !== undefined && loadDir(dir).size > 0;
  return { fetch: replayFetch(dir), mode: 'replay', baseUrl: env.SP_CONTRACT_REPLAY_BASE_URL ?? 'http://contract.invalid', hasFixtures };
}
