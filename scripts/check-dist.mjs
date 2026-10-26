// Guard: dist/ must not import Node built-ins, so the package runs in browsers and edge runtimes. Catches static
// (`from "node:x"`), side-effect (`import "node:x"`), dynamic (`import("node:x")`) and CJS (`require("node:x")`)
// forms, with the `node:` prefix or as a bare builtin (`from "fs"`, `require("path")`; list in module-markers.mjs).
//
// Module markers (MODULE_MARKERS_BY_MODULE) live in scripts/module-markers.mjs, shared with check-bundle.mjs;
// a new module adds its markers there (see the steps at the top of that file), never here.
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { MODULE_MARKERS, MODULE_MARKERS_BY_MODULE, NODE_IMPORT_RE } from './module-markers.mjs';

// CHECK_DIST_ROOT: point the guard at another directory (used only to demonstrate it fails on a planted file).
const root = process.env.CHECK_DIST_ROOT ?? fileURLToPath(new URL('../dist', import.meta.url));
const NODE_IMPORT = NODE_IMPORT_RE;
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
  console.error(`check-dist: Node built-in imports found in dist (node:x or a bare builtin):\n  ${bad.join('\n  ')}`);
  process.exit(1);
}

// `jose` is an optional peer: the main entry (and every chunk it loads) must not reference it, and the verify entry
// must import it as an external package, never bundle it.
const JOSE_IMPORT = /(?:\bfrom|\bimport|\brequire)\s*\(?\s*["']jose["']/;
const joseProblems = [];
for (const f of ['index.js', 'index.cjs']) {
  const text = readFileSync(join(root, f), 'utf8');
  if (/\bjose\b/.test(text)) joseProblems.push(`${f} references jose`);
  for (const m of text.matchAll(/(?:\bfrom|\bimport|\brequire)\s*\(?\s*["'](\.[^"']+)["']/g)) {
    const chunk = join(root, m[1]);
    if (/\bjose\b/.test(readFileSync(chunk, 'utf8'))) joseProblems.push(`${f} loads ${m[1]}, which references jose`);
  }
}
for (const f of ['verify.js', 'verify.cjs']) {
  const text = readFileSync(join(root, f), 'utf8');
  if (!JOSE_IMPORT.test(text)) joseProblems.push(`${f} does not import jose as an external`);
  if (/\bnode_modules\/jose\b|JWKSNoMatchingKey\s*=\s*class/.test(text)) joseProblems.push(`${f} appears to bundle jose`);
}
if (joseProblems.length) {
  console.error(`check-dist: jose isolation:\n  ${joseProblems.join('\n  ')}`);
  process.exit(1);
}

// The core import graph must hold no module code (importing only the main entry pulls in no module). Each marker
// must really appear in its own module's dist file, so a marker the bundler never emits cannot pass vacuously.
const vacuous = [];
for (const [mod, markers] of Object.entries(MODULE_MARKERS_BY_MODULE)) {
  for (const ext of ['js', 'cjs']) {
    const text = readFileSync(join(root, `${mod}.${ext}`), 'utf8');
    for (const m of markers) if (!text.includes(m)) vacuous.push(`dist/${mod}.${ext} lacks marker "${m}"`);
  }
}
if (vacuous.length) {
  console.error(`check-dist: vacuous module markers (not emitted in their own module file):\n  ${vacuous.join('\n  ')}`);
  process.exit(1);
}
const seen = new Set();
const leaks = [];
function follow(file) {
  if (seen.has(file)) return;
  seen.add(file);
  const text = readFileSync(file, 'utf8');
  for (const m of MODULE_MARKERS) if (text.includes(m)) leaks.push(`${relative(root, file)} contains "${m}"`);
  for (const m of text.matchAll(/(?:\bfrom|\bimport|\brequire)\s*\(?\s*["'](\.[^"']+)["']/g)) follow(resolve(dirname(file), m[1]));
}
follow(join(root, 'index.js'));
follow(join(root, 'index.cjs'));
if (leaks.length) {
  console.error(`check-dist: module code reachable from the main entry:\n  ${leaks.join('\n  ')}`);
  process.exit(1);
}
console.log('check-dist: ok');
