// Guard (spec §10, bundle-size acceptance): what an app gets when it bundles this package for the browser.
// For every entry in package.json "exports" (the main entry and each subpath), esbuild bundles a one-line app
// `export * from '<that entry's ESM dist file>'` (bundle, platform browser, ESM, nothing external, minified) and:
//   - the main entry's bundle contains no module marker (scripts/module-markers.mjs) and stays within the
//     size budget below (raw and gzip);
//   - every subpath bundle contains all of its own markers (so the marker list cannot pass vacuously) and no
//     other module's markers (except NAMES_OTHER_MODULES, documented below);
//   - no bundle resolves a Node built-in (`node:x` or a bare `fs`, `path`, ...);
//   - `jose` (optional peer) is resolved by the `./verify` bundle and by no other bundle.
// `export *` keeps every export alive, so this is the worst case for an app that imports only the core.
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';
import { MODULE_MARKERS_BY_MODULE, isNodeBuiltin } from './module-markers.mjs';

// Measured 2026-10-26 (esbuild 0.27.7, minified, `export *` of dist/index.js): raw 31,897 B, gzip 10,675 B.
// Budget = measured + 25%, rounded up. Raise it only with a reason in the commit message.
const MEASURED = { raw: 31897, gzip: 10675 };
const BUDGET = { raw: Math.ceil(MEASURED.raw * 1.25), gzip: Math.ceil(MEASURED.gzip * 1.25) };

const root = fileURLToPath(new URL('..', import.meta.url));
const require = createRequire(import.meta.url);
// esbuild comes with tsup (a devDependency); resolve it from there instead of adding a second copy.
const esbuild = createRequire(require.resolve('tsup'))('esbuild');
const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));

// Subpaths whose code names other modules' markers by design. None in this package.
const NAMES_OTHER_MODULES = new Set([]);

const problems = [];
const rows = [];

async function bundle(subpath, file) {
  const builtins = new Set();
  const jose = new Set();
  const result = await esbuild.build({
    stdin: { contents: `export * from ${JSON.stringify(join(root, file))};\n`, resolveDir: root, loader: 'js' },
    bundle: true,
    platform: 'browser',
    format: 'esm',
    target: 'es2020',
    minify: true,
    legalComments: 'none',
    write: false,
    logLevel: 'silent',
    plugins: [
      {
        name: 'record-node-builtins',
        setup(b) {
          b.onResolve({ filter: /.*/ }, (args) => {
            if (/^jose(\/|$)/.test(args.path)) jose.add(args.path);
            if (!isNodeBuiltin(args.path)) return undefined;
            builtins.add(args.path);
            return { path: args.path, external: true };
          });
        },
      },
    ],
  });
  const text = result.outputFiles[0].text;
  const raw = Buffer.byteLength(text);
  const gzip = gzipSync(text, { level: 9 }).length;
  return { subpath, text, raw, gzip, builtins: [...builtins], jose: [...jose] };
}

const entries = Object.entries(pkg.exports).map(([key, v]) => [key, v.import.default]);
if (!entries.some(([k]) => k === '.')) problems.push('package.json exports has no "." entry');

for (const [key, file] of entries) {
  const name = key === '.' ? 'index' : key.slice(2);
  let b;
  try {
    b = await bundle(key, file);
  } catch (e) {
    problems.push(`${key}: esbuild failed (${e.message.split('\n')[0]})`);
    continue;
  }
  rows.push(b);
  if (b.builtins.length) problems.push(`${key}: the browser bundle pulls Node built-ins: ${b.builtins.join(', ')}`);
  for (const [mod, markers] of Object.entries(MODULE_MARKERS_BY_MODULE)) {
    for (const m of markers) {
      const has = b.text.includes(m);
      if (mod === name && !has) problems.push(`${key}: its own marker "${m}" is not in its bundle (vacuous marker)`);
      if (mod !== name && has && !NAMES_OTHER_MODULES.has(name)) problems.push(`${key}: bundle contains "${m}" (module code of "${mod}")`);
    }
  }
  if (key === './verify' && b.jose.length === 0) problems.push('./verify: the bundle never resolves jose (jose check is vacuous)');
  if (key !== './verify' && b.jose.length) problems.push(`${key}: the bundle resolves jose (${b.jose.join(', ')}); only ./verify may`);
  if (key === '.') {
    if (b.raw > BUDGET.raw) problems.push(`.: bundle is ${b.raw} B raw, budget ${BUDGET.raw} B (measured ${MEASURED.raw} B + 25%)`);
    if (b.gzip > BUDGET.gzip) problems.push(`.: bundle is ${b.gzip} B gzip, budget ${BUDGET.gzip} B (measured ${MEASURED.gzip} B + 25%)`);
  }
}
const modulesWithoutEntry = Object.keys(MODULE_MARKERS_BY_MODULE).filter((m) => !entries.some(([k]) => k === `./${m}`));
for (const m of modulesWithoutEntry) problems.push(`module-markers.mjs lists "${m}", but package.json exports has no "./${m}"`);
for (const [k] of entries) {
  if (k !== '.' && !(k.slice(2) in MODULE_MARKERS_BY_MODULE)) problems.push(`exports "${k}" has no markers in scripts/module-markers.mjs`);
}

for (const r of rows) {
  const budget = r.subpath === '.' ? `  (budget ${BUDGET.raw} / ${BUDGET.gzip})` : '';
  console.log(`check-bundle: ${r.subpath.padEnd(14)} ${String(r.raw).padStart(7)} B raw ${String(r.gzip).padStart(6)} B gzip${budget}`);
}
if (problems.length) {
  console.error(`check-bundle:\n  ${problems.join('\n  ')}`);
  process.exit(1);
}
console.log(`check-bundle: ok (${rows.length} entries)`);
