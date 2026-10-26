// Runtime smoke test (spec §7 runtime matrix: CJS and ESM import on Node 20/22/24). For the main entry and every
// subpath in package.json "exports", loads the built package by its own name (Node package self-reference, so the
// "exports" map itself is exercised) with both `require()` and `import()`, and asserts that every documented
// export exists with the right type and that both formats expose the same names. Needs `pnpm build` first.
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const pkg = JSON.parse(readFileSync(fileURLToPath(new URL('../package.json', import.meta.url)), 'utf8'));
const require = createRequire(import.meta.url);

// Documented public runtime exports per subpath (README "API" / "Modules"). `function` covers classes.
const EXPECTED = {
  '.': {
    function: [
      'createJwtAuth',
      'userSession',
      'clientCredentials',
      'staticToken',
      'apiKey',
      'memoryStore',
      'webStorageStore',
      'ensureDeviceId',
      'createCrossTab',
      'readCookie',
      'decodeClaims',
      'unwrap',
      'findTokenPair',
      'detectChallenge',
      'SpAuthError',
      'authErrorFromResponse',
      'isSpAuthError',
    ],
    object: ['presets'],
    string: ['VERSION'],
  },
  './verify': { function: ['createVerifier'] },
  './otp': { function: ['otp'] },
  './mfa': { function: ['mfa'] },
  './oauth': { function: ['oauth', 'oauthAuthorizationCode', 'generateCodeVerifier', 'pkceChallenge'] },
  './sessions': { function: ['sessions'] },
  './account': { function: ['account'] },
  './social': { function: ['social'] },
};

const problems = [];
const exportKeys = Object.keys(pkg.exports);
for (const k of exportKeys) if (!(k in EXPECTED)) problems.push(`exports "${k}" has no EXPECTED entry in smoke-imports.mjs`);
for (const k of Object.keys(EXPECTED)) if (!exportKeys.includes(k)) problems.push(`EXPECTED "${k}" is not in package.json exports`);

for (const [sub, want] of Object.entries(EXPECTED)) {
  const spec = sub === '.' ? pkg.name : `${pkg.name}/${sub.slice(2)}`;
  const loaded = {};
  try {
    loaded.cjs = require(spec);
  } catch (e) {
    problems.push(`require("${spec}") threw: ${e.message.split('\n')[0]}`);
  }
  try {
    loaded.esm = await import(spec);
  } catch (e) {
    problems.push(`import("${spec}") threw: ${e.message.split('\n')[0]}`);
  }
  for (const [fmt, mod] of Object.entries(loaded)) {
    for (const [type, names] of Object.entries(want)) {
      for (const n of names) if (typeof mod[n] !== type) problems.push(`${fmt} ${spec}: ${n} is ${typeof mod[n]}, expected ${type}`);
    }
  }
  if (loaded.cjs && loaded.esm) {
    const names = (m) => Object.keys(m).filter((n) => n !== 'default' && n !== '__esModule').sort().join(',');
    if (names(loaded.cjs) !== names(loaded.esm)) problems.push(`${spec}: CJS exports [${names(loaded.cjs)}] differ from ESM [${names(loaded.esm)}]`);
  }
  console.log(`smoke-imports: ${spec.padEnd(36)} require ${loaded.cjs ? 'ok' : 'FAIL'}  import ${loaded.esm ? 'ok' : 'FAIL'}`);
}

if (problems.length) {
  console.error(`smoke-imports (node ${process.version}):\n  ${problems.join('\n  ')}`);
  process.exit(1);
}
console.log(`smoke-imports: ok (node ${process.version}, ${Object.keys(EXPECTED).length} entries x CJS+ESM)`);
