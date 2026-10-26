import { defineConfig } from 'tsup';

// Each module task adds its own entry here and its subpath in package.json "exports".
export default defineConfig({
  entry: { index: 'src/index.ts', verify: 'src/verify/index.ts' },
  // `jose` is an optional peer dependency: never bundle it (it is also in peerDependencies, which tsup externalises).
  external: ['jose'],
  // Share core code (SpAuthError) between entries in CJS too, so `instanceof` works across subpaths.
  splitting: true,
  format: ['esm', 'cjs'],
  target: 'es2020',
  dts: true,
  clean: true,
  sourcemap: true,
  treeshake: true,
});
