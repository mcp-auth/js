import { defineConfig, type Options } from 'tsup';

export const config = Object.freeze({
  entry: {
    'whoami/index': 'src/whoami/index.ts',
    'todo-manager/index': 'src/todo-manager/index.ts',
  },
  outDir: 'dist',
  format: ['esm'],
  dts: false,
  sourcemap: true,
  clean: true,
} satisfies Options);

export default defineConfig(config);
