# CLAUDE.md

# Git rules

- Implement on the `develop` branch (beta line). Do not commit feature work to `main`.
- `main` is for stable releases only: merge `develop` into `main` after the beta is proven, then tag and publish from `main`.
- Beta tags (`vX.Y.Z-beta.N`) come from `develop` and publish to the npm `beta` dist-tag; stable tags (`vX.Y.Z`) come from `main` and publish to `latest`.
- Never force-push, and never move or delete a published tag.

See CONTRIBUTING.md ("Git workflow and releases") for the release steps.
