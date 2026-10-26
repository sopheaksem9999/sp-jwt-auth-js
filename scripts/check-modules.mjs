// Guard (spec §7): every src/<module>/ folder, except `core`, needs a
// README.md and at least one test/<module>/*.contract.test.ts.
//
// Adding a module checklist (each step has its own guard in `pnpm check` / `pnpm vitest run`):
//   1. src/<name>/index.ts + src/<name>/README.md, and test/<name>/*.contract.test.ts   (this script);
//   2. a tsup entry and a package.json "exports" subpath (+ typesVersions)               (publint, attw);
//   3. its markers in scripts/module-markers.mjs: 1+ string literals only that module emits
//      (check-dist.mjs: present in dist/<name>.{js,cjs}, absent from the main entry graph;
//       check-bundle.mjs: present in the module's own browser bundle, absent from the core bundle);
//   4. its documented exports in scripts/smoke-imports.mjs EXPECTED                     (CJS + ESM smoke);
//   5. no Node built-in in its code                                                     (check-dist, check-bundle).
import { existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const EXEMPT = new Set(['core']);
const src = join(root, 'src');
const problems = [];

const modules = readdirSync(src, { withFileTypes: true })
  .filter((d) => d.isDirectory() && !EXEMPT.has(d.name))
  .map((d) => d.name);

for (const m of modules) {
  if (!existsSync(join(src, m, 'README.md'))) problems.push(`src/${m}/README.md is missing`);
  const testDir = join(root, 'test', m);
  const hasContract =
    existsSync(testDir) && readdirSync(testDir).some((f) => f.endsWith('.contract.test.ts'));
  if (!hasContract) problems.push(`test/${m}/*.contract.test.ts is missing`);
}

if (problems.length) {
  console.error(`check-modules:\n  ${problems.join('\n  ')}`);
  process.exit(1);
}
console.log(`check-modules: ok (${modules.length} module folder(s))`);
