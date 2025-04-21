/**
 * @fileoverview This file contains tests for the createVerifyJwt function with mocked jose module.
 * Due to the nature of ESM, it's very hard to mock a module on-demand, thus we create a separate file
 * to add the tests for the createVerifyJwt function that require the jose module to be mocked.
 */

import assert from 'node:assert';

import * as jose from 'jose';
import { describe, expect, it, vi } from 'vitest';

import { MCPAuthJwtVerificationError } from '../errors.js';

vi.mock('jose', async (importOriginal) => {
  const actual = await importOriginal<typeof jose>();
  return {
    ...actual,
    jwtVerify: vi.fn(),
  };
});

const secret = new TextEncoder().encode('super-secret-key-for-testing');
const alg = 'HS256';
const jwtVerifySpy = vi.spyOn(jose, 'jwtVerify');

const createJwt = async (payload: Record<string, unknown>) =>
  new jose.SignJWT(payload)
    .setProtectedHeader({ alg })
    .setIssuedAt()
    .setExpirationTime('1h')
    .sign(secret);

describe('createVerifyJwt() returning (mocked jose module)', () => {
  // Create a new file to mock the jose module
  it('should fallback to the default error code if the underlying error is not a JOSEError', async () => {
    jwtVerifySpy.mockRejectedValueOnce(new Error('Some unexpected error'));

    const { createVerifyJwt } = await import('./create-verify-jwt.js');
    const verifyJwt = createVerifyJwt(() => secret);
    const jwt = await createJwt({ client_id: 'client12345', sub: 'user12345' });
    try {
      await verifyJwt(jwt);
    } catch (error) {
      expect(error instanceof MCPAuthJwtVerificationError);
      assert(error instanceof MCPAuthJwtVerificationError); // Make TypeScript happy
      expect(error.cause).toHaveProperty('code', 'JWT_VERIFICATION_FAILED');
    }

    expect.assertions(2);
  });
});
