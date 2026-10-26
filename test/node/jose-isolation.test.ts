// `jose` is an optional peer: only src/verify may import it, so apps that never verify tokens never load it.
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

function files(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? files(join(dir, e.name)) : e.name.endsWith('.ts') ? [join(dir, e.name)] : [],
  );
}

describe('jose isolation', () => {
  it('is imported only from src/verify', () => {
    const src = join(process.cwd(), 'src');
    const offenders = files(src).filter(
      (f) => !f.startsWith(join(src, 'verify')) && /(?:from|import|require)\s*\(?\s*['"]jose['"/]/.test(readFileSync(f, 'utf8')),
    );
    expect(offenders).toEqual([]);
  });
});
