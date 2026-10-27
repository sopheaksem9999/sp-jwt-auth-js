// Spec §10: "Neither package imports the other. @sokpheak/sp-jwt-auth installs and works without @sokpheak/sp-laravel-api."
// Node-only (reads files, spawns node), so the edge project excludes *.node.test.ts.
import { spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';

const root = fileURLToPath(new URL('../..', import.meta.url));
const SELF = '@sokpheak/sp-jwt-auth';
const OTHER = '@sokpheak/sp-laravel-api';
const IMPORT_OF_OTHER = new RegExp(`(?:\\bfrom|\\bimport|\\brequire)\\s*\\(?\\s*["'\`]${OTHER.replace('/', '\\/')}(?:["'\`/])`);

function files(dir: string, keep: (f: string) => boolean): string[] {
  if (!existsSync(dir)) return [];
  return readdirSync(dir, { withFileTypes: true, recursive: true })
    .filter((e) => e.isFile() && keep(e.name))
    .map((e) => join(e.parentPath, e.name));
}

/** Where `text` imports OTHER (static, side-effect, dynamic or CJS). */
const importsOther = (text: string): boolean => IMPORT_OF_OTHER.test(text);

describe('independence: no import of the other package', () => {
  it('the detector catches every import form (non-vacuous)', () => {
    for (const s of [`import x from '${OTHER}';`, `import '${OTHER}/sub';`, `await import("${OTHER}")`, `require('${OTHER}')`, `export * from "${OTHER}"`]) {
      expect(importsOther(s), s).toBe(true);
    }
    expect(importsOther(`// works with ${OTHER} too`)).toBe(false);
    expect(importsOther(`import x from '${OTHER}-extra';`)).toBe(false);
  });

  it('src/** never imports it', () => {
    const src = files(join(root, 'src'), (f) => /\.(ts|tsx|js|mjs|cjs)$/.test(f));
    expect(src.length).toBeGreaterThan(5);
    const hits = src.filter((f) => importsOther(readFileSync(f, 'utf8'))).map((f) => relative(root, f));
    expect(hits).toEqual([]);
  });

  it('package.json lists it in no dependency field', () => {
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as Record<string, unknown>;
    expect(pkg.name).toBe(SELF);
    for (const field of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies', 'peerDependenciesMeta', 'bundleDependencies', 'bundledDependencies']) {
      const v = pkg[field];
      const names = Array.isArray(v) ? v : Object.keys((v as Record<string, unknown> | undefined) ?? {});
      expect(names, field).not.toContain(OTHER);
    }
  });

  it('the built dist never imports it', ({ skip }) => {
    const dist = files(join(root, 'dist'), (f) => /\.(js|cjs|d\.ts|d\.cts)$/.test(f));
    if (dist.length === 0) {
      if (process.env.REQUIRE_DIST === '1') throw new Error('dist/ is missing; run pnpm build (REQUIRE_DIST=1)');
      skip('dist/ not built');
    }
    expect(dist.filter((f) => importsOther(readFileSync(f, 'utf8'))).map((f) => relative(root, f))).toEqual([]);
  });
});

/** Copies package.json + dist into `<dir>/node_modules/<SELF>`: no workspace links, no dependencies. */
function installAlone(dir: string): void {
  const pkgDir = join(dir, 'node_modules', ...SELF.split('/'));
  mkdirSync(pkgDir, { recursive: true });
  cpSync(join(root, 'package.json'), join(pkgDir, 'package.json'));
  cpSync(join(root, 'dist'), join(pkgDir, 'dist'), { recursive: true });
  writeFileSync(join(dir, 'package.json'), '{"name":"independence-probe","private":true}');
}

/**
 * Runs Node in `dir` with a clean NODE_PATH: exits 2 with "OTHER_RESOLVABLE" when OTHER resolves from there, else
 * require()s and import()s SELF and checks its main export, printing "independent-ok".
 */
function probe(dir: string): { status: number | null; stdout: string; stderr: string } {
  const script = [
    `let otherFound = true; try { require.resolve(${JSON.stringify(OTHER)}); } catch { otherFound = false; }`,
    "if (otherFound) { console.error('OTHER_RESOLVABLE'); process.exit(2); }",
    `const cjs = require(${JSON.stringify(SELF)});`,
    `import(${JSON.stringify(SELF)}).then((esm) => {`,
    "  for (const m of [cjs, esm]) if (typeof m.createJwtAuth !== 'function') throw new Error('createJwtAuth missing');",
    "  console.log('independent-ok');",
    '}).catch((e) => { console.error(e); process.exit(1); });',
  ].join('\n');
  const env: NodeJS.ProcessEnv = { ...process.env, NODE_PATH: '' };
  delete env.NODE_OPTIONS;
  // Under Deno or Bun (running this suite), process.execPath is that runtime: the probe is a Node install check.
  const nodeBin = /[\\/]node(\.exe)?$/.test(process.execPath) ? process.execPath : 'node';
  const r = spawnSync(nodeBin, ['-e', script], { cwd: dir, env, encoding: 'utf8' });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

function requireDist(skip: (note?: string) => void): void {
  if (!existsSync(join(root, 'dist', 'index.cjs'))) {
    if (process.env.REQUIRE_DIST === '1') throw new Error('dist/ is missing; run pnpm build (REQUIRE_DIST=1)');
    skip('dist/ not built');
  }
}

describe(`${SELF} works without ${OTHER} installed`, () => {
  const tmp = mkdtempSync(join(tmpdir(), 'sp-independence-'));
  afterAll(() => rmSync(tmp, { recursive: true, force: true }));

  it('require() and import() of the main entry from a directory holding only this package', ({ skip }) => {
    requireDist(skip);
    const dir = join(tmp, 'alone');
    installAlone(dir);
    const r = probe(dir);
    expect(r.stderr).toBe('');
    expect(r.stdout.trim()).toBe('independent-ok');
    expect(r.status).toBe(0);
  });

  it(`the probe detects ${OTHER} when it IS resolvable (non-vacuous)`, ({ skip }) => {
    requireDist(skip);
    const dir = join(tmp, 'with-other');
    installAlone(dir);
    const otherDir = join(dir, 'node_modules', ...OTHER.split('/'));
    mkdirSync(otherDir, { recursive: true });
    writeFileSync(join(otherDir, 'package.json'), JSON.stringify({ name: OTHER, version: '0.0.0', main: 'index.js' }));
    writeFileSync(join(otherDir, 'index.js'), 'module.exports = {};');
    const r = probe(dir);
    expect(r.stderr.trim()).toBe('OTHER_RESOLVABLE');
    expect(r.status).toBe(2);
  });
});
