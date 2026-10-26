import { mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { beforeEach, describe, expect, it } from 'vitest';
import { entryKey, hashBody, liveOrReplay, replayFetch } from './replay';
import type { RecordedEntry } from './replay';
import { scrub } from './scrub';

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
    store(dir, entry({ method: 'POST', query: '', bodyHash: hashBody(body) }));
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
  it('removes tokens, secrets, Authorization and Set-Cookie (case-insensitive, nested)', () => {
    const e: RecordedEntry = {
      request: {
        method: 'POST',
        path: '/oauth/token',
        query: '',
        headers: { AUTHORIZATION: 'Bearer abc', Accept: 'application/json' },
        body: { client: { Secret: 's3', id: 'c1' }, refresh_token: 'r' },
      },
      response: {
        status: 200,
        headers: { 'Set-Cookie': 'sid=1', 'set-cookie2': 'keep', 'Content-Type': 'application/json' },
        body: { data: { access_token: 'a', refresh_token: 'r', secret: 's', user: { id: 1 }, list: [{ access_token: 'z', n: 1 }] } },
      },
    };
    const out = scrub(e);
    const json = JSON.stringify(out);
    for (const bad of ['"a"', 'Bearer', 'sid=1', '"s3"', '"s"', '"z"', '"r"']) expect(json).not.toContain(bad);
    expect(out.request.headers).toEqual({ Accept: 'application/json' });
    expect(out.response.headers).toEqual({ 'set-cookie2': 'keep', 'Content-Type': 'application/json' });
    expect(out.response.body).toEqual({ data: { user: { id: 1 }, list: [{ n: 1 }] } });
    expect(out.request.body).toEqual({ client: { id: 'c1' } });
  });

  it('scrubs JSON held in string bodies and does not mutate its input', () => {
    const e = entry({}, { body: '{"access_token":"a","ok":true}' });
    const out = scrub(e);
    expect(JSON.parse(out.response.body as string)).toEqual({ ok: true });
    expect(e.response.body).toContain('access_token');
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
    expect(raw).not.toMatch(/tok|sid=1|secret-token|Bearer/);
    expect(JSON.parse(raw).response.body).toEqual({ data: { id: 1 } });

    const back = liveOrReplay({ env: { SP_CONTRACT_BACKEND_VERSION: 'v9' }, fixturesRoot: root });
    expect(await (await back.fetch('http://be.test/api/items')).json()).toEqual({ data: { id: 1 } });
  });
});
