// Spec §10: "Neither package imports the other. @sopheak/sp-jwt-auth installs and works without @sopheak/sp-laravel-api."
// Node-only (reads files, spawns node), so the edge project excludes *.node.test.ts.
import { spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';

const root = fileURLToPath(new URL('../..', import.meta.url));
const SELF = '@sopheak/sp-jwt-auth';
const OTHER = '@sopheak/sp-laravel-api';
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

describe(`${SELF} works without ${OTHER} installed`, () => {
  const tmp = mkdtempSync(join(tmpdir(), 'sp-independence-'));
  afterAll(() => rmSync(tmp, { recursive: true, force: true }));

  it('require() and import() of the main entry from a directory holding only this package', ({ skip }) => {
    if (!existsSync(join(root, 'dist', 'index.cjs'))) {
      if (process.env.REQUIRE_DIST === '1') throw new Error('dist/ is missing; run pnpm build (REQUIRE_DIST=1)');
      skip('dist/ not built');
    }
    // node_modules/<SELF> = package.json + dist only: no workspace links, no dependencies, no OTHER.
    const pkgDir = join(tmp, 'node_modules', ...SELF.split('/'));
    mkdirSync(pkgDir, { recursive: true });
    cpSync(join(root, 'package.json'), join(pkgDir, 'package.json'));
    cpSync(join(root, 'dist'), join(pkgDir, 'dist'), { recursive: true });
    writeFileSync(join(tmp, 'package.json'), '{"name":"independence-probe","private":true}');
    const script = [
      `const cjs = require('${SELF}');`,
      "let otherFound = true; try { require.resolve('${other}'); } catch { otherFound = false; }",
      "if (otherFound) throw new Error('the other package is resolvable from the probe directory');",
      `import('${SELF}').then((esm) => {`,
      `  for (const m of [cjs, esm]) if (typeof m.createJwtAuth !== 'function') throw new Error('createJwtAuth missing');`,
      "  console.log('independent-ok');",
      '}).catch((e) => { console.error(e); process.exit(1); });',
    ].join('\n');
    const env: NodeJS.ProcessEnv = { ...process.env, NODE_PATH: '' };
    delete env.NODE_OPTIONS;
    // Under Deno or Bun (running this suite), process.execPath is that runtime: the probe is a Node install check.
    const nodeBin = /[\\/]node(\.exe)?$/.test(process.execPath) ? process.execPath : 'node';
    const r = spawnSync(nodeBin, ['-e', script], { cwd: tmp, env, encoding: 'utf8' });
    expect(r.stderr).toBe('');
    expect(r.stdout.trim()).toBe('independent-ok');
    expect(r.status).toBe(0);
  });
});
