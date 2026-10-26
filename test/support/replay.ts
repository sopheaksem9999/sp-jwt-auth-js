// Contract-test helpers: replay recorded HTTP exchanges, or hit a live backend (optionally recording).
// Copied into each package on purpose: packages never import from each other.
// Node-only (node:fs, node:crypto); runs in the vitest `node` project only.
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { SCRUBBED, REQUEST_HEADER_ALLOWLIST, isSecretKey, scrub, scrubParams, scrubPath, scrubQuery, scrubValue, sortKeys } from './scrub';

/** One recorded exchange. Stored as one JSON file per request, named `<entryKey>.json`. */
export interface RecordedEntry {
  request: {
    method: string;
    /** URL path without host. */
    path: string;
    /** Scrubbed query string with pairs sorted, e.g. `a=1&b=2` (no leading `?`). */
    query: string;
    /** sha256 (hex) of the canonical, already scrubbed request body; absent when there is none. */
    bodyHash?: string;
    /** Allowlist only: accept, content-type. */
    headers?: Record<string, string>;
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

/** Stable key: sha256 of method, path, scrubbed sorted query and canonical body hash (first 24 hex chars). */
export function entryKey(r: Pick<RecordedEntry['request'], 'method' | 'path' | 'query' | 'bodyHash'>): string {
  return createHash('sha256')
    .update([r.method.toUpperCase(), scrubPath(r.path), scrubQuery(r.query), r.bodyHash ?? ''].join('\n'))
    .digest('hex')
    .slice(0, 24);
}

function canonicalText(s: string, contentType: string): string | undefined {
  if (s === '') return undefined;
  if (contentType.toLowerCase().includes('application/x-www-form-urlencoded')) return `form:${scrubParams(s, true)}`;
  let parsed: unknown;
  try {
    parsed = JSON.parse(s);
  } catch {
    parsed = undefined;
  }
  // Only JSON objects/arrays can be scrubbed field by field. Any other text (or a bare JSON scalar) may itself be a
  // secret, and hashing it would make the match key depend on it, so it is refused rather than recorded.
  if (typeof parsed !== 'object' || parsed === null) {
    throw new Error(
      `contract replay: refusing a text request body with content type "${contentType === '' ? '(none)' : contentType}": only form-urlencoded and JSON object/array bodies are supported`,
    );
  }
  return `json:${JSON.stringify(sortKeys(scrubValue(parsed)))}`;
}

function canonicalFormData(fd: FormData): string {
  const entries: unknown[] = [];
  fd.forEach((v, k) => {
    if (typeof v === 'string') entries.push([k, isSecretKey(k) ? SCRUBBED : v]);
    else entries.push([k, { file: v.name, size: v.size }]);
  });
  return `formdata:${JSON.stringify(entries)}`;
}

/**
 * Canonical form of a request body, computed AFTER scrubbing secret fields and never containing a
 * multipart boundary. Throws for stream bodies (they cannot be hashed without being consumed).
 */
export async function canonicalBody(b: unknown, contentType: string): Promise<string | undefined> {
  if (b === undefined || b === null) return undefined;
  if (typeof b === 'string') return canonicalText(b, contentType);
  if (b instanceof URLSearchParams) return canonicalText(b.toString(), 'application/x-www-form-urlencoded');
  if (typeof FormData !== 'undefined' && b instanceof FormData) return canonicalFormData(b);
  let bytes: Uint8Array | undefined;
  if (typeof Blob !== 'undefined' && b instanceof Blob) bytes = new Uint8Array(await b.arrayBuffer());
  else if (b instanceof ArrayBuffer) bytes = new Uint8Array(b);
  else if (ArrayBuffer.isView(b)) bytes = new Uint8Array(b.buffer, b.byteOffset, b.byteLength);
  if (bytes !== undefined) return `bytes:${createHash('sha256').update(bytes).digest('hex')}`;
  if (typeof ReadableStream !== 'undefined' && b instanceof ReadableStream) {
    throw new Error('contract replay: ReadableStream request bodies are not supported (they cannot be hashed without being consumed)');
  }
  throw new Error('contract replay: unsupported request body type');
}

async function requestBody(input: Parameters<typeof fetch>[0], init: RequestInit | undefined): Promise<string | undefined> {
  const req = input instanceof Request ? input : undefined;
  const ct = new Headers(init?.headers ?? req?.headers).get('content-type') ?? '';
  if (init?.body !== undefined && init.body !== null) return canonicalBody(init.body, ct);
  if (req !== undefined && req.body !== null) {
    return canonicalBody(ct.toLowerCase().startsWith('multipart/form-data') ? await req.clone().formData() : await req.clone().text(), ct);
  }
  return undefined;
}

async function describeRequest(
  input: Parameters<typeof fetch>[0],
  init: RequestInit | undefined,
): Promise<{ url: string; method: string; request: RecordedEntry['request'] }> {
  const req = input instanceof Request ? input : undefined;
  const url = req?.url ?? String(input);
  const method = (init?.method ?? req?.method ?? 'GET').toUpperCase();
  const canon = await requestBody(input, init);
  const u = new URL(url);
  const headers: Record<string, string> = {};
  new Headers(init?.headers ?? req?.headers).forEach((v, k) => {
    if (!REQUEST_HEADER_ALLOWLIST.has(k)) return;
    headers[k] = k === 'content-type' && v.toLowerCase().startsWith('multipart/') ? 'multipart/form-data' : v;
  });
  const request: RecordedEntry['request'] = { method, path: scrubPath(u.pathname), query: scrubQuery(u.search), headers };
  if (canon !== undefined) request.bodyHash = hashBody(canon);
  return { url, method, request };
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

/** Natural order: digit runs compare numerically, so `v0.10` sorts after `v0.9`. */
export function naturalCompare(a: string, b: string): number {
  const pa = a.split(/(\d+)/);
  const pb = b.split(/(\d+)/);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? '';
    const y = pb[i] ?? '';
    if (x === y) continue;
    if (i % 2 === 1) return Number(x) - Number(y) || (x < y ? -1 : 1);
    return x < y ? -1 : 1;
  }
  return 0;
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
    if (record && (version === undefined || version === '')) {
      throw new Error('SP_CONTRACT_RECORD=1 requires SP_CONTRACT_BACKEND_VERSION (the backend tag, used as the fixture folder)');
    }
    const f = record ? recordingFetch(live, join(root, version as string)) : live;
    return { fetch: f, mode: 'live', baseUrl: url.replace(/\/+$/, ''), hasFixtures: false };
  }

  const versions = existsSync(root)
    ? readdirSync(root, { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => d.name).sort(naturalCompare)
    : [];
  const chosen = version ?? versions[versions.length - 1];
  const dir = join(root, chosen ?? '');
  const hasFixtures = chosen !== undefined && loadDir(dir).size > 0;
  return { fetch: replayFetch(dir), mode: 'replay', baseUrl: env.SP_CONTRACT_REPLAY_BASE_URL ?? 'http://contract.invalid', hasFixtures };
}
