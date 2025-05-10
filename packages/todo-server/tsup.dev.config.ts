import { defineConfig } from 'tsup';

import { config as baseConfig } from './tsup.config.js';

export default defineConfig({
  ...baseConfig,
  watch: ['src/**/*.ts', '.env', '../../.env', '*.config.ts'],
  onSuccess: 'node ./dist/index.js',
});
