// Keeps the §4.5 RULE_MAP honest: every referenced deep test file exists and declares every referenced title as a
// `describe(...)` or `it(...)`/`test(...)` title (any quote style), and refresh-rules.test.ts has one test per rule
// key. A renamed or deleted deep test fails here. Node-only (reads files).
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { RULE_MAP } from './rule-map';

const root = fileURLToPath(new URL('../..', import.meta.url));

/** `true` when `source` declares `title` as a describe / it / test title (modifiers like `.skipIf(x)` allowed). */
function declaresTitle(source: string, title: string): boolean {
  return ["'", '"', '`'].some((q) => {
    const quoted = q + (q === "'" ? title.replace(/'/g, "\\'") : title) + q;
    return new RegExp(`\\b(?:describe|it|test)(?:\\.\\w+(?:\\([^)]*\\))?)*\\(\\s*${escapeRe(quoted)}`).test(source);
  });
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

describe('§4.5 RULE_MAP references real tests', () => {
  it('covers rules 1-6, each with at least one reference', () => {
    expect(Object.keys(RULE_MAP).map((k) => k.split(':')[0])).toEqual(['rule 1', 'rule 2', 'rule 3', 'rule 4', 'rule 5', 'rule 6']);
    for (const refs of Object.values(RULE_MAP)) expect(refs.flatMap((r) => r.titles).length).toBeGreaterThan(0);
  });

  it.each(Object.entries(RULE_MAP))('%s: every referenced title exists', (_rule, refs) => {
    const missing: string[] = [];
    for (const { file, titles } of refs) {
      const path = join(root, file);
      if (!existsSync(path)) {
        missing.push(`${file} (file missing)`);
        continue;
      }
      const source = readFileSync(path, 'utf8');
      for (const t of titles) if (!declaresTitle(source, t)) missing.push(`${file}: "${t}"`);
    }
    expect(missing).toEqual([]);
  });

  it('refresh-rules.test.ts has one test per rule key', () => {
    const source = readFileSync(join(root, 'test/acceptance/refresh-rules.test.ts'), 'utf8');
    for (const rule of Object.keys(RULE_MAP)) expect(source, rule).toContain(`it('${rule.split(':')[0]}:`);
  });

  it('the title detector is not vacuous', () => {
    const src = "describe('outer', () => { it(\"a 'quoted' title\", () => {}); it('x \\'y\\' z', () => {}); });";
    expect(declaresTitle(src, 'outer')).toBe(true);
    expect(declaresTitle(src, "a 'quoted' title")).toBe(true);
    expect(declaresTitle(src, "x 'y' z")).toBe(true);
    expect(declaresTitle(src, 'outer renamed')).toBe(false);
    expect(declaresTitle(src, 'a quoted title')).toBe(false);
  });
});
