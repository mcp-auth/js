import { expect } from 'vitest';

/**
 * Builds an asymmetric matcher for mcp-auth errors, matching the error class by `name` and the
 * error `code` property. Matching against an error instance would compare the `cause` property
 * deeply, which is not what the tests are interested in.
 */
export const matchError = (name: string, code: string): Error =>
  /* Vitest types `objectContaining` as `any`; cast it to satisfy the `toThrowError` signature. */
  // eslint-disable-next-line no-restricted-syntax
  expect.objectContaining({ name, code }) as Error;
