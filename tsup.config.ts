import { defineConfig } from 'tsup';

// Each module task adds its own entry here and its subpath in package.json "exports".
export default defineConfig({
  entry: { index: 'src/index.ts' },
  format: ['esm', 'cjs'],
  target: 'es2020',
  dts: true,
  clean: true,
  sourcemap: true,
  treeshake: true,
});
