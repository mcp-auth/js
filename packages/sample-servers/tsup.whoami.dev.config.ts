import { defineConfig } from 'tsup';

import { config as baseConfig } from './tsup.config.js';

export default defineConfig({
  ...baseConfig,
  entry: { 'todo-manager/index': 'src/todo-manager/todo-service/index.ts' },
  watch: ['src/todo-manager/**/*.ts', '.env', '../../.env'],
  onSuccess: 'node ./dist/todo-manager/index.js',
});
