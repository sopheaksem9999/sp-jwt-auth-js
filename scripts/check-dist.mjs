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
console.log('check-dist: ok');
