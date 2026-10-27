# CLAUDE.md

# Git rules

- Implement on the `develop` branch (beta line). Do not commit feature work to `main`.
- `main` is for stable releases only: merge `develop` into `main` after the beta is proven.
- Releases are automatic: pushing a bumped `package.json` version to `develop` (beta, `-beta.N`) or `main` (stable) publishes it, creates the `v<version>` tag and a GitHub Release with notes from the commits. Do not create release tags by hand. Use conventional commit subjects (`feat:`, `fix:`, `docs:`).
- Never force-push, and never move or delete a published tag.

See CONTRIBUTING.md ("Git workflow and releases") for the release steps.
