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

describe('scrub hardening (Task 18)', () => {
  const root = (): string => join(dir, 'fixtures');
  const respond = (body: unknown, headers: Record<string, string> = {}): typeof fetch => async () =>
    new Response(JSON.stringify(body), { headers: { 'content-type': 'application/json', ...headers } });
  const record = (f: typeof fetch) =>
    liveOrReplay({ env: { SP_CONTRACT_URL: 'http://x.test', SP_CONTRACT_RECORD: '1', SP_CONTRACT_BACKEND_VERSION: 'v1' }, fixturesRoot: root(), liveFetch: f });
  const replay = () => liveOrReplay({ env: { SP_CONTRACT_BACKEND_VERSION: 'v1' }, fixturesRoot: root() });

  it('normalises key names (case, - and _) before matching secret keys, on disk and in matching', async () => {
    const secrets = { accessToken: 'AT-1', 'access-token': 'AT-2', idToken: 'IT-1', 'Client-Secret': 'CS-1', refreshToken: 'RT-1', API_KEY: 'AK-1', twoFa: 'keep' };
    await record(respond({ data: secrets })).fetch('http://x.test/api/n?accessToken=Q-1&client-secret=Q-2', { method: 'POST', body: JSON.stringify(secrets) });
    const disk = allFiles(root());
    for (const lit of ['AT-1', 'AT-2', 'IT-1', 'CS-1', 'RT-1', 'AK-1', 'Q-1', 'Q-2']) expect(disk).not.toContain(lit);
    expect(disk).toContain('keep');
    const other = Object.fromEntries(Object.keys(secrets).map((k) => [k, k === 'twoFa' ? 'keep' : 'DIFFERENT']));
    expect((await replay().fetch('http://x.test/api/n?client-secret=z&accessToken=y', { method: 'POST', body: JSON.stringify(other) })).status).toBe(200);
  });

  it('scrubs the new response headers x-auth-token, x-api-key, x-refresh-token (any case)', async () => {
    await record(respond({ ok: 1 }, { 'X-Auth-Token': 'HDR-1', 'x-api-key': 'HDR-2', 'X-Refresh-Token': 'HDR-3', 'x-keep': 'visible' })).fetch('http://x.test/api/h');
    const disk = allFiles(root());
    for (const lit of ['HDR-1', 'HDR-2', 'HDR-3']) expect(disk).not.toContain(lit);
    expect(disk).toContain('visible');
  });

  it('scrubs the Location fragment as well as the query', () => {
    const e = entry({}, { headers: { Location: 'https://app.test/cb?code=C-1&n=1#access_token=F-1&state=S-1&refresh_token=F-2&keep=ok' } });
    const loc = scrub(e).response.headers.Location as string;
    for (const lit of ['C-1', 'F-1', 'S-1', 'F-2']) expect(loc).not.toContain(lit);
    expect(loc).toContain('keep=ok');
    expect(scrub(entry({}, { headers: { Location: 'https://app.test/cb#access_token=F-3' } })).response.headers.Location).not.toContain('F-3');
    expect(scrub(entry({}, { headers: { Location: 'https://app.test/app#/inbox' } })).response.headers.Location).toBe('https://app.test/app#/inbox');
  });

  it('scrubs the token/hash segment of /password/reset/<token> and /email/verify/<id>/<hash> (rule: path, Location; id kept)', async () => {
    const f = respond({ ok: 1 }, { Location: 'https://app.test/password/reset/LOC-TOK?email=a%40b.c' });
    await record(f).fetch('http://x.test/api/v2/password/reset/RESET-TOK?email=a%40b.c');
    await record(f).fetch('http://x.test/email/verify/12/VERIFY-HASH?signature=sig');
    const disk = allFiles(root());
    for (const lit of ['RESET-TOK', 'VERIFY-HASH', 'LOC-TOK']) expect(disk).not.toContain(lit);
    expect(disk).toContain('/email/verify/12/[scrubbed]');
    expect(disk).toContain('/api/v2/password/reset/[scrubbed]');
    expect((await replay().fetch('http://other.test/api/v2/password/reset/ANOTHER?email=a%40b.c')).status).toBe(200);
    expect((await replay().fetch('http://other.test/email/verify/12/OTHERHASH?signature=sig')).status).toBe(200);
    await expect(replay().fetch('http://other.test/email/verify/13/OTHERHASH?signature=sig')).rejects.toThrow(/unrecorded/);
  });

  it('refuses text bodies that are neither form nor JSON objects, naming the content type, before calling the backend', async () => {
    let called = false;
    const spy: typeof fetch = async (...a) => {
      called = true;
      return respond({})(...a);
    };
    const r = record(spy);
    await expect(r.fetch('http://x.test/api/t', { method: 'POST', body: 'password=hunter2 raw', headers: { 'content-type': 'text/plain' } })).rejects.toThrow(/text\/plain/);
    await expect(r.fetch('http://x.test/api/t', { method: 'POST', body: 'tok-123' })).rejects.toThrow(/refus/i);
    await expect(r.fetch('http://x.test/api/t', { method: 'POST', body: '"just-a-secret-string"', headers: { 'content-type': 'application/json' } })).rejects.toThrow(/refus/i);
    await expect(replay().fetch('http://x.test/api/t', { method: 'POST', body: 'x', headers: { 'content-type': 'text/csv' } })).rejects.toThrow(/text\/csv/);
    expect(called).toBe(false);
  });

  it('scrubs code, state, token, otp only on the request side; business fields in responses survive', async () => {
    const body = { code: 'E1', state: 'open', otp: 'visible-otp', nested: { code: 'E2' } };
    await record(respond(body)).fetch('http://x.test/api/r?code=RQ-1&state=RQ-2&token=RQ-3&otp=RQ-4', {
      method: 'POST',
      body: JSON.stringify({ code: 'RB-1', state: 'RB-2', token: 'RB-3', otp: 'RB-4', keep: 1 }),
    });
    const disk = allFiles(root());
    for (const lit of ['RQ-1', 'RQ-2', 'RQ-3', 'RQ-4', 'RB-1', 'RB-2', 'RB-3', 'RB-4']) expect(disk).not.toContain(lit);
    expect(JSON.parse(disk).response.body).toEqual(body);
    // request side is value-independent for matching
    const again = await replay().fetch('http://x.test/api/r?otp=a&token=b&state=c&code=d', {
      method: 'POST',
      body: JSON.stringify({ keep: 1, otp: 'x', token: 'y', state: 'z', code: 'w' }),
    });
    expect(await again.json()).toEqual(body);
  });

  it('keeps the literal response body {"code":"E1","state":"open"} intact through scrub', () => {
    expect(scrub(entry({}, { body: { code: 'E1', state: 'open' } })).response.body).toEqual({ code: 'E1', state: 'open' });
    expect(JSON.parse(scrub(entry({}, { body: '{"code":"E1","state":"open"}' })).response.body as string)).toEqual({ code: 'E1', state: 'open' });
  });

  it('still scrubs both-sides secrets in responses, and a string `token` field; recurses into an object `token`', () => {
    const out = scrub(
      entry({}, { body: { token: { access_token: 'a', refresh_token: 'r', expires_in: 60 }, secret: 's', api_key: 'k', '2fa_token': 't', password: 'p', id_token: 'i', client_secret: 'c' } }),
    ).response.body as Record<string, unknown>;
    expect(out.token).toEqual({ access_token: SCRUBBED, refresh_token: SCRUBBED, expires_in: 60 });
    for (const k of ['secret', 'api_key', '2fa_token', 'password', 'id_token', 'client_secret']) expect(out[k]).toBe(SCRUBBED);
    expect((scrub(entry({}, { body: { token: 'opaque-string' } })).response.body as { token: string }).token).toBe(SCRUBBED);
  });
});
