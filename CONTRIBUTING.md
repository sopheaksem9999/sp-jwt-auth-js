# Contributing

- Node 22.13+ and pnpm for development (pnpm 12 and Vitest 5 need it); the published package supports Node 20+.
- `pnpm install`, then `pnpm lint`, `pnpm typecheck`, `pnpm test`, `pnpm check` must all pass.
- A new module adds a `src/<module>/` folder with a `README.md`, a `test/<module>/*.contract.test.ts`, an entry in `tsup.config.ts` and a subpath in `package.json` `exports`. `pnpm check` enforces this.
- Source in `src/` must not use Node-only APIs or `node:` imports.
- Add a changeset (`pnpm changeset`) for user-visible changes.

## Git workflow and releases

- `main` holds stable, released code only. Never commit to it directly.
- Do all implementation on `develop` (or a feature branch merged into `develop`). `develop` is the beta line.
- Releases are automatic: a push to `main` or `develop` publishes the `package.json` version if no `v<version>` tag exists yet, then creates that tag and a GitHub Release. Release notes are generated from the commits since the previous tag (a summary, the `CHANGELOG.md` section, and commits grouped as features, fixes, docs, tests and other), so write conventional commit subjects (`feat:`, `fix:`, `docs:`).
- Beta: on `develop`, run `pnpm changeset pre enter beta` once, then `pnpm changeset version`, commit and push. A version with a `-beta.N` suffix releases from `develop` to the `beta` dist-tag (`npm i <pkg>@beta`) and is marked a GitHub pre-release.
- Stable: when the beta is proven, run `pnpm changeset pre exit` and `pnpm changeset version` on `develop`, merge `develop` into `main` and push. A version without a suffix releases only from `main`, to `latest`.
- A push whose version already has a tag, or whose version belongs to the other branch, is skipped, so ordinary pushes never publish. Nothing is published unless the version was bumped.
- Never force-push, and never move or delete a published tag.

## Secret scanning

- CI and the release workflow run gitleaks over the full git history and the working tree (`.gitleaks.toml` extends the default rules). A finding blocks the release. Run `gitleaks git . --config .gitleaks.toml --redact` locally before pushing. Never commit real keys; test fixtures use obviously fake values, and an allowlist entry in `.gitleaks.toml` must name the exact fake value.
