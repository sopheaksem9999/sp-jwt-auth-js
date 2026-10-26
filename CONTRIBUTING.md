# Contributing

- Node 22.13+ and pnpm for development (pnpm 12 and Vitest 5 need it); the published package supports Node 20+.
- `pnpm install`, then `pnpm lint`, `pnpm typecheck`, `pnpm test`, `pnpm check` must all pass.
- A new module adds a `src/<module>/` folder with a `README.md`, a `test/<module>/*.contract.test.ts`, an entry in `tsup.config.ts` and a subpath in `package.json` `exports`. `pnpm check` enforces this.
- Source in `src/` must not use Node-only APIs or `node:` imports.
- Add a changeset (`pnpm changeset`) for user-visible changes.
