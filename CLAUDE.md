# CLAUDE.md

# Git rules

- Implement on the `develop` branch (beta line). Do not commit feature work to `main`.
- `main` is for stable releases only: merge `develop` into `main` after the beta is proven.
- Releases are automatic: pushing a bumped `package.json` version to `develop` (beta, `-beta.N`) or `main` (stable) publishes it, creates the `v<version>` tag and a GitHub Release with notes from the commits. Do not create release tags by hand. Use conventional commit subjects (`feat:`, `fix:`, `docs:`).
- Never force-push, and never move or delete a published tag.

See CONTRIBUTING.md ("Git workflow and releases") for the release steps.

## Public repo hygiene

- This repository is public. No README, doc, comment, test, example, commit message or release note may name a client project; use neutral example names (`Acme`, `example.com`, `invoices`) and the `sp` prefix for project-style names (for example `presets.spSaas`).
- `pnpm check` runs `scripts/check-neutral-names.mjs`. The forbidden-name list is **not** in the repository: it comes from the `FORBIDDEN_NAMES` environment variable (a GitHub Actions secret in CI; set it in your shell locally, comma-separated). The script reports `file:line` only, never the name. Without the variable it warns and passes; set `FORBIDDEN_NAMES_REQUIRED=1` to make a missing list fail.
