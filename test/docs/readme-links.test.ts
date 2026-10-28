import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const root = resolve(__dirname, '../..');

/** GitHub-style heading slug. */
function slug(heading: string): string {
  return heading
    .trim()
    .toLowerCase()
    .replace(/`/g, '')
    .replace(/\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/[^\p{L}\p{N}\s_-]/gu, '')
    .replace(/\s/g, '-');
}

function anchors(md: string): Set<string> {
  const out = new Set<string>();
  let fence = false;
  for (const line of md.split('\n')) {
    if (/^```/.test(line)) fence = !fence;
    if (fence) continue;
    const m = /^#{1,6}\s+(.*)$/.exec(line);
    if (m) out.add(slug(m[1]!));
  }
  return out;
}

function links(md: string): string[] {
  const out: string[] = [];
  let fence = false;
  for (const line of md.split('\n')) {
    if (/^```/.test(line)) fence = !fence;
    if (fence) continue;
    for (const m of line.replace(/`[^`]*`/g, '').matchAll(/\]\(([^)\s]+)\)/g)) out.push(m[1]!);
  }
  return out;
}

const files = ['README.md', ...readdirSync(join(root, 'src')).map((d) => join('src', d, 'README.md')).filter((f) => existsSync(join(root, f)))];

describe('README links', () => {
  for (const file of files) {
    it(`${file}: every relative link and anchor resolves`, () => {
      const md = readFileSync(join(root, file), 'utf8');
      const broken: string[] = [];
      for (const link of links(md)) {
        if (/^[a-z][a-z0-9+.-]*:/i.test(link)) continue; // external
        const [path, hash] = link.split('#') as [string, string | undefined];
        const target = path === '' ? join(root, file) : resolve(root, dirname(file), path);
        if (!existsSync(target)) {
          broken.push(link);
          continue;
        }
        if (hash && target.endsWith('.md') && !anchors(readFileSync(target, 'utf8')).has(hash)) broken.push(link);
      }
      expect(broken).toEqual([]);
    });
  }
});
