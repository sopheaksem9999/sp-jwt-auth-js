// Public-repo hygiene: fails when a tracked file or a commit message in the pushed range contains a forbidden name.
// The list comes from the FORBIDDEN_NAMES environment variable (comma-separated, case-insensitive) and is never stored
// in the repo; matches are reported as file:line plus the list position only, because CI logs of a public repo are public.
// Without the variable the check warns and passes, unless FORBIDDEN_NAMES_REQUIRED=1 (set it in CI once the secret exists).
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const names = (process.env.FORBIDDEN_NAMES ?? '')
  .split(',')
  .map((n) => n.trim().toLowerCase())
  .filter(Boolean);

if (names.length === 0) {
  const required = process.env.FORBIDDEN_NAMES_REQUIRED === '1';
  console.log(`check-neutral-names: FORBIDDEN_NAMES is not set; ${required ? 'failing (required)' : 'skipped'}.`);
  process.exit(required ? 1 : 0);
}

const git = (...args) => execFileSync('git', args, { encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 });
const hits = [];
const scan = (label, text) => {
  text.split('\n').forEach((line, i) => {
    const low = line.toLowerCase();
    names.forEach((name, idx) => {
      if (low.includes(name)) hits.push(`${label}:${i + 1} (forbidden name #${idx + 1})`);
    });
  });
};

for (const file of git('ls-files', '-z').split('\0').filter(Boolean)) {
  let text;
  try {
    text = readFileSync(file, 'utf8');
  } catch {
    continue;
  }
  if (text.includes('\0')) continue; // binary
  scan(file, text);
}

const range = process.env.NEUTRAL_NAMES_COMMIT_RANGE; // e.g. origin/main..HEAD; unset = commit messages are not scanned
if (range) scan(`commit messages ${range}`, git('log', '--format=%B', range));

if (hits.length > 0) {
  console.error('check-neutral-names: forbidden names found:');
  for (const h of hits) console.error(`  ${h}`);
  process.exit(1);
}
console.log(`check-neutral-names: ok (${names.length} names, tracked files scanned).`);
