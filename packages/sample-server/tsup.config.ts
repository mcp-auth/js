import { type Options } from 'tsup';

export const config = Object.freeze({
  entry: ['src/index.ts'],
  outDir: 'dist',
  format: ['esm'],
  dts: false,
  sourcemap: true,
  clean: true,
} satisfies Options);
