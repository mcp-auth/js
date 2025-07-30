import { defineConfig } from 'tsup';

import { config as baseConfig } from './tsup.config.js';

export default defineConfig({
  ...baseConfig,
  entry: { 'whoami/index': 'src/whoami/index.ts' },
  watch: ['src/whoami/**/*.ts', '.env'],
  onSuccess: 'node ./dist/whoami/index.js',
});
