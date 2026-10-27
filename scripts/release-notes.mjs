// Prints GitHub release notes for the current HEAD: a summary, the CHANGELOG.md section for this version
// (written by `changeset version`) and every commit since the previous tag, grouped by conventional-commit type.
// Usage: node scripts/release-notes.mjs <version> [previousTag]
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';

const [version, prev] = process.argv.slice(2);
if (!version) throw new Error('usage: release-notes.mjs <version> [previousTag]');

const git = (...args) => execFileSync('git', args, { encoding: 'utf8' }).trim();
const range = prev ? `${prev}..HEAD` : 'HEAD';
const commits = git('log', '--no-merges', '--pretty=format:%h\t%s', range)
  .split('\n')
  .filter(Boolean)
  .map((line) => {
    const [sha, ...rest] = line.split('\t');
    return { sha, subject: rest.join('\t') };
  })
  .filter((c) => !/^chore(\(.*\))?: release /.test(c.subject));

const groups = [
  ['Features', /^feat(\(.*\))?!?:/],
  ['Fixes', /^fix(\(.*\))?!?:/],
  ['Docs', /^docs(\(.*\))?:/],
  ['Tests', /^test(\(.*\))?:/],
  ['Other changes', /./],
];
const buckets = new Map(groups.map(([name]) => [name, []]));
for (const c of commits) {
  const [name] = groups.find(([, re]) => re.test(c.subject));
  buckets.get(name).push(c);
}

const stat = prev ? git('diff', '--shortstat', `${prev}..HEAD`) : '';
const out = [`## Summary`, ``];
out.push(
  `${commits.length} commit${commits.length === 1 ? '' : 's'}${prev ? ` since ${prev}` : ' (first release)'}` +
    (stat ? `: ${stat}.` : '.'),
);
const counts = groups.map(([n]) => [n, buckets.get(n).length]).filter(([, n]) => n > 0);
if (counts.length) out.push(``, counts.map(([n, k]) => `${k} ${n.toLowerCase()}`).join(', ') + '.');

if (existsSync('CHANGELOG.md')) {
  const log = readFileSync('CHANGELOG.md', 'utf8');
  const start = log.indexOf(`## ${version}\n`);
  if (start !== -1) {
    const rest = log.slice(start + `## ${version}\n`.length);
    const end = rest.search(/^## /m);
    const section = (end === -1 ? rest : rest.slice(0, end)).trim();
    if (section) out.push(``, `## Changelog`, ``, section);
  }
}

out.push(``, `## Commits`);
for (const [name] of groups) {
  const list = buckets.get(name);
  if (!list.length) continue;
  out.push(``, `### ${name}`, ``, ...list.map((c) => `- ${c.subject} (${c.sha})`));
}
console.log(out.join('\n'));
