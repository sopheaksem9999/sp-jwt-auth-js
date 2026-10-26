// Guard (spec §7): every src/<module>/ folder, except `core`, needs a
// README.md and at least one test/<module>/*.contract.test.ts.
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
