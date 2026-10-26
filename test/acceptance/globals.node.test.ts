// Spec §10: no `window`, `document`, `localStorage` (and friends) outside the files that feature-detect them.
// An AST scan (TypeScript compiler API) of src/**: a reference is an identifier read in value position (type-only
// uses are erased and never touch the global), a property read off a global object (`globalThis.document`,
// `(globalThis as X).document`, `self['localStorage']`), any computed read off a global object
// (`globalThis[kind]`, which can reach any of them), or one of the names as a string literal in value position.
// Comments and docs never count. A new file that references one fails until it is added to ALLOWED with a reason;
// an ALLOWED file that no longer references any of them fails too, so the list stays tight.
// Node-only (reads files), so the edge project excludes *.node.test.ts.
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';
import { describe, expect, it } from 'vitest';

const root = fileURLToPath(new URL('../..', import.meta.url));
const BROWSER_GLOBALS = new Set(['window', 'document', 'localStorage', 'sessionStorage', 'navigator', 'BroadcastChannel']);
const GLOBAL_OBJECTS = new Set(['globalThis', 'self', 'window']);

/** Files allowed to reference browser globals, each feature-detecting (guarded `typeof`/try, safe without them). */
const ALLOWED: Record<string, string> = {
  'src/core/stores.ts': 'webStorageStore: reads globalThis[localStorage|sessionStorage] in try/catch; missing or blocked storage acts as empty',
  'src/core/cookie.ts': 'cookie transport: document.cookie (readCookie, tab-context check) and the BroadcastChannel presence check, guarded',
  'src/core/crosstab.ts': 'cross-tab helpers: navigator.locks, BroadcastChannel and the storage event, each detected with a fallback',
  'src/oauth/index.ts': 'PKCE pending-login store: sessionStorage when it works, else in-memory',
};

function unwrap(e: ts.Expression): ts.Expression {
  let x = e;
  while (ts.isParenthesizedExpression(x) || ts.isAsExpression(x) || ts.isNonNullExpression(x) || ts.isSatisfiesExpression(x) || ts.isTypeAssertionExpression(x)) {
    x = x.expression;
  }
  return x;
}

const isGlobalObject = (e: ts.Expression): boolean => {
  const x = unwrap(e);
  return ts.isIdentifier(x) && GLOBAL_OBJECTS.has(x.text);
};

function inTypePosition(n: ts.Node): boolean {
  for (let p: ts.Node | undefined = n.parent; p; p = p.parent) {
    if (ts.isTypeNode(p) || ts.isInterfaceDeclaration(p) || ts.isTypeAliasDeclaration(p)) return true;
    if (ts.isExpression(p) && !ts.isExpressionWithTypeArguments(p)) return false;
  }
  return false;
}

/** Browser-global references in one source text, as `line: what`. */
function browserGlobalRefs(fileName: string, text: string): string[] {
  const sf = ts.createSourceFile(fileName, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const out: string[] = [];
  const at = (n: ts.Node, what: string): void => {
    out.push(`${sf.getLineAndCharacterOfPosition(n.getStart(sf)).line + 1}: ${what}`);
  };
  const visit = (n: ts.Node): void => {
    if (ts.isIdentifier(n) && BROWSER_GLOBALS.has(n.text) && !inTypePosition(n)) {
      const p = n.parent;
      const isMemberName = (ts.isPropertyAccessExpression(p) && p.name === n) || ((ts.isPropertyAssignment(p) || ts.isPropertyDeclaration(p) || ts.isMethodDeclaration(p) || ts.isPropertySignature(p)) && p.name === n);
      if (isMemberName) {
        if (ts.isPropertyAccessExpression(p) && isGlobalObject(p.expression)) at(n, `global.${n.text}`);
      } else if (!ts.isImportSpecifier(p) && !ts.isExportSpecifier(p)) {
        at(n, n.text);
      }
    }
    if (ts.isElementAccessExpression(n) && isGlobalObject(n.expression)) {
      const k = n.argumentExpression;
      if (ts.isStringLiteralLike(k)) {
        if (BROWSER_GLOBALS.has(k.text)) at(n, `global['${k.text}']`);
      } else {
        at(n, 'global[<computed>]');
      }
    }
    if (ts.isStringLiteralLike(n) && BROWSER_GLOBALS.has(n.text) && !inTypePosition(n) && !ts.isElementAccessExpression(n.parent)) {
      at(n, `'${n.text}' literal`);
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return out;
}

function srcFiles(): string[] {
  return readdirSync(join(root, 'src'), { withFileTypes: true, recursive: true })
    .filter((e) => e.isFile() && /\.(ts|tsx|mts|cts)$/.test(e.name))
    .map((e) => relative(root, join(e.parentPath, e.name)).split(sep).join('/'));
}

describe('browser globals (spec §10)', () => {
  it('the scanner sees every reference form and ignores types and comments (non-vacuous)', () => {
    const hits = (s: string): number => browserGlobalRefs('x.ts', s).length;
    expect(hits('window.location.href;')).toBe(1);
    expect(hits('const c = document.cookie;')).toBe(1);
    expect(hits('localStorage.getItem("k");')).toBe(1);
    expect(hits('const n = (globalThis as { navigator?: unknown }).navigator;')).toBe(1);
    expect(hits('new globalThis.BroadcastChannel("x");')).toBe(1);
    expect(hits('const s = self["sessionStorage"];')).toBe(1);
    expect(hits('const s = globalThis[kind];')).toBe(1);
    expect(hits('use("localStorage");')).toBe(1);
    expect(hits('typeof document === "undefined";')).toBe(1);
    expect(hits('// window and document in a comment\n/** localStorage */ const a = 1;')).toBe(0);
    expect(hits('let ch: BroadcastChannel | null = null; type K = "localStorage";')).toBe(0);
    expect(hits('const o = { document: 1 }; o.document; interface I { navigator: string }')).toBe(0);
    expect(hits('globalThis.fetch; globalThis.crypto.randomUUID();')).toBe(0);
  });

  it('src/** references them only in the allowed, feature-detecting files', () => {
    const offenders: string[] = [];
    const seenAllowed = new Set<string>();
    for (const f of srcFiles()) {
      const refs = browserGlobalRefs(f, readFileSync(join(root, f), 'utf8'));
      if (refs.length === 0) continue;
      if (f in ALLOWED) seenAllowed.add(f);
      else offenders.push(...refs.map((r) => `${f}:${r}`));
    }
    expect(offenders).toEqual([]);
    // Every allowed file must still reference one, or it comes off the list.
    expect(Object.keys(ALLOWED).filter((f) => !seenAllowed.has(f))).toEqual([]);
  });
});
