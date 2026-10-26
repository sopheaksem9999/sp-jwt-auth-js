// Runtime smoke test for Deno and Bun (spec §7 runtime matrix). Imports the BUILT ESM entries by file URL (no npm
// resolution, no Node globals needed) and runs a tiny flow against a fake fetch:
//   deno run --allow-read scripts/deno-smoke.ts      bun run scripts/deno-smoke.ts
// Needs `pnpm build` first. Any failed check throws, so the process exits non-zero.
// `./verify` is not imported: it needs the `jose` peer resolved from npm, which a file-URL import cannot do.
const runtime = globalThis as { Deno?: { version?: { deno?: string } }; Bun?: { version?: string } };
const name = runtime.Bun ? `bun ${runtime.Bun.version}` : runtime.Deno ? `deno ${runtime.Deno.version?.deno}` : 'unknown runtime';

const entry = (file: string): string => new URL(`../dist/${file}`, import.meta.url).href;
const core = await import(entry('index.js'));
const otpModule = await import(entry('otp.js'));

function check(ok: boolean, what: string): void {
  if (!ok) throw new Error(`deno-smoke (${name}): ${what}`);
  console.log(`  ok  ${what}`);
}

const b64url = (s: string): string => btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const jwt = (exp: number): string => `${b64url('{"alg":"none"}')}.${b64url(JSON.stringify({ sub: '7', exp }))}.sig`;
const now = (): number => Math.floor(Date.now() / 1000);

console.log(`deno-smoke: @sopheak/sp-jwt-auth on ${name}`);
const seen: string[] = [];
const near = jwt(now() + 30);
const fresh = jwt(now() + 900);
const fakeFetch = async (input: RequestInfo | URL): Promise<Response> => {
  const path = new URL(String(input)).pathname;
  seen.push(path);
  const pair = path.endsWith('/refresh') ? { access_token: fresh, refresh_token: 'r2', expires_in: 900 } : { access_token: near, refresh_token: 'r1', expires_in: 30 };
  return new Response(JSON.stringify({ token: pair }), { status: 200, headers: { 'Content-Type': 'application/json' } });
};
const auth = core.createJwtAuth({
  baseUrl: 'https://api.test',
  ...core.presets.spJwtTest,
  mode: core.userSession({ storage: core.memoryStore() }),
  fetch: fakeFetch,
});
check((await auth.login({ email: 'a@b.c', password: 'x' })).status === 'authenticated', 'createJwtAuth().login() authenticates');
const tokens = await Promise.all([auth.getAccessToken(), auth.getAccessToken(), auth.getAccessToken()]);
check(tokens.every((t) => t === fresh), 'getAccessToken() refreshes proactively inside the ahead window');
check(seen.filter((p) => p.endsWith('/refresh')).length === 1, 'concurrent callers share one refresh');
check(auth.getState().claims?.sub === '7', 'state carries the decoded claims');
check(core.readCookie('x') === null, 'readCookie() is null without a document');
check(typeof otpModule.otp(auth).request === 'function', 'the otp subpath loads and binds to the instance');
await auth.logout();
check(auth.getState().status === 'anonymous', 'logout() ends the session');
console.log(`deno-smoke: ok (${name})`);
