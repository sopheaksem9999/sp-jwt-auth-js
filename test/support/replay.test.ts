import { mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { beforeEach, describe, expect, it } from 'vitest';
import { entryKey, hashBody, liveOrReplay, naturalCompare, replayFetch } from './replay';
import type { RecordedEntry } from './replay';
import { SCRUBBED, scrub } from './scrub';

function entry(over: Partial<RecordedEntry['request']> = {}, res: Partial<RecordedEntry['response']> = {}): RecordedEntry {
  return {
    request: { method: 'GET', path: '/api/items', query: 'per_page=2', ...over },
    response: { status: 200, headers: { 'content-type': 'application/json', 'x-trace': 'abc' }, body: { success: true, data: [1, 2] }, ...res },
  };
}

function store(dir: string, e: RecordedEntry): void {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, `${entryKey(e.request)}.json`), JSON.stringify(e));
}

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'replay-'));
});

describe('replayFetch', () => {
  it('returns the recorded body, status and headers', async () => {
    store(dir, entry({}, { status: 201 }));
    const res = await replayFetch(dir)('http://x.test/api/items?per_page=2');
    expect(res.status).toBe(201);
    expect(res.headers.get('x-trace')).toBe('abc');
    expect(await res.json()).toEqual({ success: true, data: [1, 2] });
  });

  it('throws on an unrecorded request, naming method and URL', async () => {
    store(dir, entry());
    await expect(replayFetch(dir)('http://x.test/api/other', { method: 'DELETE' })).rejects.toThrow(
      /DELETE http:\/\/x\.test\/api\/other/,
    );
  });

  it('matches regardless of host and query parameter order', async () => {
    store(dir, entry({ query: 'a=1&b=2' }));
    const f = replayFetch(dir);
    expect((await f('http://other.test/api/items?b=2&a=1')).status).toBe(200);
    await expect(f('http://other.test/api/items?a=1&b=3')).rejects.toThrow(/unrecorded/);
  });

  it('matches by method', async () => {
    store(dir, entry());
    await expect(replayFetch(dir)('http://x.test/api/items?per_page=2', { method: 'POST' })).rejects.toThrow(/POST/);
  });

  it('matches by body hash', async () => {
    const body = JSON.stringify({ name: 'Acme' });
    store(dir, entry({ method: 'POST', query: '', bodyHash: hashBody(`json:${body}`) }));
    const f = replayFetch(dir);
    expect((await f('http://x.test/api/items', { method: 'POST', body })).status).toBe(200);
    await expect(f('http://x.test/api/items', { method: 'POST', body: '{"name":"Other"}' })).rejects.toThrow(/unrecorded/);
    await expect(f('http://x.test/api/items', { method: 'POST' })).rejects.toThrow(/unrecorded/);
  });

  it('treats a missing fixture directory as empty', async () => {
    await expect(replayFetch(join(dir, 'nope'))('http://x.test/a')).rejects.toThrow(/GET http:\/\/x\.test\/a/);
  });
});

describe('scrub', () => {
  it('replaces tokens, secrets and secret headers (case-insensitive, nested) and keeps only allowlisted request headers', () => {
    const e: RecordedEntry = {
      request: {
        method: 'POST',
        path: '/oauth/token',
        query: 'access_token=qq&x=1',
        headers: { AUTHORIZATION: 'Bearer abc', Accept: 'application/json', 'X-Custom': 'keep?', Cookie: 'c=1' },
      },
      response: {
        status: 200,
        headers: { 'Set-Cookie': 'sid=1', 'set-cookie2': 'keep', 'X-XSRF-TOKEN': 'xs', 'Content-Type': 'application/json' },
        body: { data: { access_token: 'a', refresh_token: 'r', Secret: 's', password: 'pw', user: { id: 1 }, list: [{ id_token: 'z', n: 1 }] } },
      },
    };
    const out = scrub(e);
    expect(out.request.headers).toEqual({ Accept: 'application/json' });
    expect(out.request.query).toBe('access_token=%5Bscrubbed%5D&x=1');
    expect(out.response.headers).toEqual({ 'Set-Cookie': SCRUBBED, 'set-cookie2': 'keep', 'X-XSRF-TOKEN': SCRUBBED, 'Content-Type': 'application/json' });
    expect(out.response.body).toEqual({
      data: { access_token: SCRUBBED, refresh_token: SCRUBBED, Secret: SCRUBBED, password: SCRUBBED, user: { id: 1 }, list: [{ id_token: SCRUBBED, n: 1 }] },
    });
  });

  it('scrubs JSON held in string bodies, Location query secrets, and does not mutate its input', () => {
    const e = entry({}, { body: '{"access_token":"a","ok":true}', headers: { Location: 'https://app.test/cb?code=XYZ&next=/home' } });
    const out = scrub(e);
    expect(JSON.parse(out.response.body as string)).toEqual({ access_token: SCRUBBED, ok: true });
    expect(out.response.headers.Location).toBe('https://app.test/cb?code=%5Bscrubbed%5D&next=%2Fhome');
    expect(e.response.body).toContain('"a"');
  });
});

const API = 'http://x.test/oauth/token';
const form = (secret: string): URLSearchParams =>
  new URLSearchParams({ grant_type: 'password', username: 'u', password: secret, client_secret: `cs-${secret}` });

function allFiles(root: string): string {
  let out = '';
  for (const v of readdirSync(root)) for (const f of readdirSync(join(root, v))) out += readFileSync(join(root, v, f), 'utf8');
  return out;
}

describe('body canonicalisation and recording', () => {
  const root = (): string => join(dir, 'fixtures');
  const okFetch: typeof fetch = async () => new Response('{"data":{"access_token":"RESP-TOKEN","id":7}}', { headers: { 'content-type': 'application/json' } });
  const record = (f: typeof fetch = okFetch) =>
    liveOrReplay({ env: { SP_CONTRACT_URL: 'http://x.test', SP_CONTRACT_RECORD: '1', SP_CONTRACT_BACKEND_VERSION: 'v1' }, fixturesRoot: root(), liveFetch: f });
  const replay = () => liveOrReplay({ env: { SP_CONTRACT_BACKEND_VERSION: 'v1' }, fixturesRoot: root() });

  it('never writes form-encoded secrets; replay ignores the secret value', async () => {
    await record().fetch(API, { method: 'POST', body: form('hunter2'), headers: { 'content-type': 'application/x-www-form-urlencoded' } });
    const disk = allFiles(root());
    for (const lit of ['hunter2', 'cs-hunter2', 'RESP-TOKEN']) expect(disk).not.toContain(lit);
    const res = await replay().fetch(API, { method: 'POST', body: form('different'), headers: { 'content-type': 'application/x-www-form-urlencoded' } });
    expect((await res.json()).data.id).toBe(7);
    await expect(
      replay().fetch(API, { method: 'POST', body: new URLSearchParams({ grant_type: 'refresh', password: 'hunter2' }) }),
    ).rejects.toThrow(/unrecorded/);
  });

  it('scrubs query-string secrets on disk and replay still matches', async () => {
    await record().fetch('http://x.test/api/cb?access_token=SECRETQ&code=CODE1&page=2');
    const disk = allFiles(root());
    expect(disk).not.toContain('SECRETQ');
    expect(disk).not.toContain('CODE1');
    expect((await replay().fetch('http://x.test/api/cb?page=2&code=OTHER&access_token=ZZ')).status).toBe(200);
  });

  it('keys FormData by fields and file metadata, not by multipart boundary', async () => {
    const fd = (): FormData => {
      const f = new FormData();
      f.set('name', 'Acme');
      f.set('password', 'pw-secret');
      f.set('doc', new File(['hello'], 'a.txt'));
      return f;
    };
    await record().fetch('http://x.test/api/upload', { method: 'POST', body: fd() });
    expect(allFiles(root())).not.toContain('pw-secret');
    expect((await replay().fetch('http://x.test/api/upload', { method: 'POST', body: fd() })).status).toBe(200);
    // Two Request objects carry two different random boundaries.
    const r1 = new Request('http://x.test/api/upload', { method: 'POST', body: fd() });
    const r2 = new Request('http://x.test/api/upload', { method: 'POST', body: fd() });
    expect(r1.headers.get('content-type')).not.toBe(r2.headers.get('content-type'));
    expect((await replay().fetch(r1)).status).toBe(200);
    expect((await replay().fetch(r2)).status).toBe(200);
  });

  it('is independent of JSON key order and round-trips a POST', async () => {
    await record().fetch('http://x.test/api/items', { method: 'POST', body: JSON.stringify({ b: 1, a: { d: 2, c: 3 }, password: 'p1' }) });
    expect(allFiles(root())).not.toContain('p1');
    const res = await replay().fetch('http://x.test/api/items', { method: 'POST', body: JSON.stringify({ password: 'p2', a: { c: 3, d: 2 }, b: 1 }) });
    expect(res.status).toBe(200);
  });

  it('hashes binary bodies by their bytes', async () => {
    await record().fetch('http://x.test/api/bin', { method: 'POST', body: new Uint8Array([1, 2, 255]) });
    expect((await replay().fetch('http://x.test/api/bin', { method: 'POST', body: new Uint8Array([1, 2, 255]).buffer })).status).toBe(200);
    await expect(replay().fetch('http://x.test/api/bin', { method: 'POST', body: new Uint8Array([1, 2, 254]) })).rejects.toThrow(/unrecorded/);
  });

  it('throws before calling the backend for a ReadableStream body', async () => {
    let called = false;
    const spy: typeof fetch = async (...a) => {
      called = true;
      return okFetch(...a);
    };
    const stream = new ReadableStream({ start: (c) => c.close() });
    await expect(
      record(spy).fetch('http://x.test/api/s', { method: 'POST', body: stream, duplex: 'half' } as RequestInit),
    ).rejects.toThrow(/ReadableStream/);
    expect(called).toBe(false);
  });

  it('writes only allowlisted request headers', async () => {
    await record().fetch('http://x.test/api/h', { headers: { Authorization: 'Bearer LEAK', Accept: 'application/json', 'X-CSRF-TOKEN': 'LEAK2', 'X-Other': 'LEAK3' } });
    const disk = allFiles(root());
    for (const lit of ['LEAK', 'LEAK2', 'LEAK3', 'Bearer']) expect(disk).not.toContain(lit);
    const entryOnDisk = JSON.parse(disk) as RecordedEntry;
    expect(entryOnDisk.request.headers).toEqual({ accept: 'application/json' });
  });

  it('refuses to record without a backend version', () => {
    expect(() => liveOrReplay({ env: { SP_CONTRACT_URL: 'http://x.test', SP_CONTRACT_RECORD: '1' }, fixturesRoot: root(), liveFetch: okFetch })).toThrow(/SP_CONTRACT_BACKEND_VERSION/);
  });

  it('picks the naturally latest version folder', async () => {
    for (const [v, status] of [['v0.9', 209], ['v0.10', 210]] as const) store(join(root(), v), entry({}, { status }));
    const r = liveOrReplay({ env: {}, fixturesRoot: root() });
    expect((await r.fetch('http://x.test/api/items?per_page=2')).status).toBe(210);
    expect(['v0.10', 'v0.9', 'v0.2'].sort(naturalCompare)).toEqual(['v0.2', 'v0.9', 'v0.10']);
  });
});

describe('liveOrReplay', () => {
  it('is replay mode with an empty fixture set when nothing is configured', async () => {
    const r = liveOrReplay({ env: {}, fixturesRoot: join(dir, 'fixtures') });
    expect(r.mode).toBe('replay');
    expect(r.hasFixtures).toBe(false);
    await expect(r.fetch('http://x.test/a')).rejects.toThrow(/unrecorded/);
  });

  it('replays the fixtures of the selected backend version', async () => {
    const root = join(dir, 'fixtures');
    store(join(root, 'v1'), entry());
    store(join(root, 'v2'), entry({}, { status: 202 }));
    const r = liveOrReplay({ env: { SP_CONTRACT_BACKEND_VERSION: 'v1' }, fixturesRoot: root });
    expect(r.hasFixtures).toBe(true);
    expect((await r.fetch('http://x.test/api/items?per_page=2')).status).toBe(200);
  });

  it('is live when SP_CONTRACT_URL is set and records scrubbed entries only on request', async () => {
    const root = join(dir, 'fixtures');
    const fake: typeof fetch = async () =>
      new Response(JSON.stringify({ data: { access_token: 'tok', id: 1 } }), {
        status: 200,
        headers: { 'content-type': 'application/json', 'set-cookie': 'sid=1' },
      });
    const live = liveOrReplay({ env: { SP_CONTRACT_URL: 'http://be.test' }, fixturesRoot: root, liveFetch: fake });
    expect(live.mode).toBe('live');
    expect(live.baseUrl).toBe('http://be.test');
    await live.fetch('http://be.test/api/items');
    expect(() => readdirSync(root)).toThrow();

    const rec = liveOrReplay({
      env: { SP_CONTRACT_URL: 'http://be.test', SP_CONTRACT_RECORD: '1', SP_CONTRACT_BACKEND_VERSION: 'v9' },
      fixturesRoot: root,
      liveFetch: fake,
    });
    const res = await rec.fetch('http://be.test/api/items', { headers: { Authorization: 'Bearer secret-token' } });
    expect(await res.json()).toEqual({ data: { access_token: 'tok', id: 1 } });
    const files = readdirSync(join(root, 'v9'));
    expect(files).toHaveLength(1);
    const raw = readFileSync(join(root, 'v9', files[0] as string), 'utf8');
    expect(raw).not.toMatch(/"tok"|sid=1|secret-token|Bearer/);
    expect(JSON.parse(raw).response.body).toEqual({ data: { access_token: SCRUBBED, id: 1 } });

    const back = liveOrReplay({ env: { SP_CONTRACT_BACKEND_VERSION: 'v9' }, fixturesRoot: root });
    expect(await (await back.fetch('http://be.test/api/items')).json()).toEqual({ data: { access_token: SCRUBBED, id: 1 } });
  });
});
