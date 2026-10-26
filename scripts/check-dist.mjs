// Guard: dist/ must not import Node built-ins (`node:` specifiers), so the
// package runs in browsers and edge runtimes. Catches static (`from "node:x"`),
// side-effect (`import "node:x"`), dynamic (`import("node:x")`) and CJS
// (`require("node:x")`) forms.
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../dist', import.meta.url));
const NODE_IMPORT = /(?:\bfrom|\bimport|\brequire)\s*\(?\s*["']node:/;
const bad = [];

function walk(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(full);
    } else if (NODE_IMPORT.test(readFileSync(full, 'utf8'))) {
      bad.push(relative(root, full).split(sep).join('/'));
    }
  }
}

try {
  walk(root);
} catch (e) {
  console.error(`check-dist: cannot read dist/ (${e.message}). Run the build first.`);
  process.exit(1);
}
if (bad.length) {
  console.error(`check-dist: node: imports found in dist:\n  ${bad.join('\n  ')}`);
  process.exit(1);
}
console.log('check-dist: ok');
