import assert from 'node:assert';

import { SignJWT } from 'jose';
import { describe, expect, it } from 'vitest';

import { MCPAuthTokenVerificationError } from '../errors.js';

import { createVerifyJwt } from './create-verify-jwt.js';

const secret = new TextEncoder().encode('super-secret-key-for-testing');
const alg = 'HS256';

const createJwt = async (payload: Record<string, unknown>) =>
  new SignJWT(payload)
    .setProtectedHeader({ alg })
    .setIssuedAt()
    .setExpirationTime('1h')
    .sign(secret);

describe('createVerifyJwt() returning error handling', () => {
  it('should throw an error if signature verification fails', async () => {
    const verifyJwt = createVerifyJwt(() => new TextEncoder().encode('wrong-secret-key'));
    const jwt = await createJwt({ client_id: 'client12345', sub: 'user12345' });

    try {
      await verifyJwt(jwt);
    } catch (error) {
      expect(error instanceof MCPAuthTokenVerificationError);
      assert(error instanceof MCPAuthTokenVerificationError); // Make TypeScript happy
      expect(error.code).toBe('invalid_token');
      expect(error.cause).toHaveProperty('code', 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED');
    }

    expect.assertions(3);
  });

  it('should throw an error if the JWT payload does not contain the `iss` field or it is malformed', async () => {
    const verifyJwt = createVerifyJwt(() => secret);
    const jwts = await Promise.all([
      createJwt({ client_id: 'client12345', sub: 'user12345' }),
      createJwt({ iss: 12_345, client_id: 'client12345', sub: 'user12345' }),
      createJwt({ iss: '', client_id: 'client12345', sub: 'user12345' }),
    ]);
    const error = new MCPAuthTokenVerificationError('invalid_token', {
      cause: 'The JWT payload does not contain the `iss` field or it is malformed.',
    });

    await Promise.all(jwts.map(async (jwt) => expect(verifyJwt(jwt)).rejects.toThrow(error)));
  });

  it('should throw an error if the JWT payload does not contain the `client_id` field or it is malformed', async () => {
    const verifyJwt = createVerifyJwt(() => secret);
    const jwts = await Promise.all([
      createJwt({ iss: 'https://logto.io/', sub: 'user12345' }),
      createJwt({ iss: 'https://logto.io/', client_id: 12_345, sub: 'user12345' }),
      createJwt({ iss: 'https://logto.io/', client_id: '', sub: 'user12345' }),
    ]);
    const error = new MCPAuthTokenVerificationError('invalid_token', {
      cause: 'The JWT payload does not contain the `client_id` field or it is malformed.',
    });

    await Promise.all(jwts.map(async (jwt) => expect(verifyJwt(jwt)).rejects.toThrow(error)));
  });

  it('should throw an error if the JWT payload does not contain the `sub` field or it is malformed', async () => {
    const verifyJwt = createVerifyJwt(() => secret);
    const jwts = await Promise.all([
      createJwt({ iss: 'https://logto.io/', client_id: 'client12345' }),
      createJwt({ iss: 'https://logto.io/', client_id: 'client12345', sub: 12_345 }),
      createJwt({ iss: 'https://logto.io/', client_id: 'client12345', sub: '' }),
    ]);
    const error = new MCPAuthTokenVerificationError('invalid_token', {
      cause: 'The JWT payload does not contain the `sub` field or it is malformed.',
    });

    await Promise.all(jwts.map(async (jwt) => expect(verifyJwt(jwt)).rejects.toThrow(error)));
  });
});

const expectJwtPayload = (jwt: string, claims: Record<string, unknown>, scopes: string[]) => ({
  issuer: claims.iss,
  clientId: claims.client_id,
  scopes,
  token: jwt,
  audience: claims.aud,
  claims: {
    ...claims,
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
    iat: expect.any(Number),
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
    exp: expect.any(Number),
  },
  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
  expiresAt: expect.any(Number),
  subject: claims.sub,
});

describe('createVerifyJwt() returning normal behavior', () => {
  it('should return the verified JWT payload with string `scope` field', async () => {
    const verifyJwt = createVerifyJwt(() => secret);
    const claims = Object.freeze({
      iss: 'https://logto.io/',
      client_id: 'client12345',
      sub: 'user12345',
      scope: 'read write',
      aud: 'audience12345',
    });
    const jwt = await createJwt(claims);
    const result = await verifyJwt(jwt);
    expect(result).toEqual(expectJwtPayload(jwt, claims, ['read', 'write']));
  });

  it('should return the verified JWT payload with array `scope` field', async () => {
    const verifyJwt = createVerifyJwt(() => secret);
    const claims = Object.freeze({
      iss: 'https://logto.io/',
      client_id: 'client12345',
      sub: 'user12345',
      scope: ['read', 'write'],
    });
    const jwt = await createJwt(claims);
    const result = await verifyJwt(jwt);
    expect(result).toEqual(expectJwtPayload(jwt, claims, ['read', 'write']));
  });

  it('should return the verified JWT payload with `scopes` field when `scope` is not present', async () => {
    const verifyJwt = createVerifyJwt(() => secret);
    const claims = Object.freeze({
      iss: 'https://logto.io/',
      client_id: 'client12345',
      sub: 'user12345',
      scopes: ['read', 'write'],
    });
    const jwt = await createJwt(claims);
    const result = await verifyJwt(jwt);
    expect(result).toEqual(expectJwtPayload(jwt, claims, ['read', 'write']));
  });

  it('should return the verified JWT payload when `scope` and `scopes` are not present', async () => {
    const verifyJwt = createVerifyJwt(() => secret);
    const claims = Object.freeze({
      iss: 'https://logto.io/',
      client_id: 'client12345',
      sub: 'user12345',
      aud: 'audience12345',
    });
    const jwt = await createJwt(claims);
    const result = await verifyJwt(jwt);
    expect(result).toEqual(expectJwtPayload(jwt, claims, []));
  });
});
