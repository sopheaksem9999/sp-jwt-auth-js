# Contributing

- Node 22.13+ and pnpm for development (pnpm 12 and Vitest 5 need it); the published package supports Node 20+.
- `pnpm install`, then `pnpm lint`, `pnpm typecheck`, `pnpm test`, `pnpm check` must all pass.
- A new module adds a `src/<module>/` folder with a `README.md`, a `test/<module>/*.contract.test.ts`, an entry in `tsup.config.ts` and a subpath in `package.json` `exports`. `pnpm check` enforces this.
- Source in `src/` must not use Node-only APIs or `node:` imports.
- Add a changeset (`pnpm changeset`) for user-visible changes.

## Git workflow and releases

- `main` holds stable, released code only. Never commit to it directly.
- Do all implementation on `develop` (or a feature branch merged into `develop`). `develop` is the beta line.
- Beta release: on `develop`, run `pnpm changeset pre enter beta` once, then `pnpm changeset version`, commit and tag `v<version>-beta.<n>` (for example `v0.2.0-beta.1`). The release workflow publishes it to the `beta` dist-tag, so `npm i <pkg>@beta` gets it and `latest` is untouched.
- Stable release: when the beta is proven, run `pnpm changeset pre exit` on `develop`, merge `develop` into `main`, run `pnpm changeset version` there, commit and tag `v<version>` on `main`. The workflow publishes to `latest`.
- The release workflow refuses a stable tag that is not on `main` and a beta tag that is not on `develop`, and a tag that differs from `package.json` `version`.
- Never force-push or move a tag that was published.
