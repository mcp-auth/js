import { SignJWT } from 'jose';
import * as jose from 'jose';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { MCPAuthBearerAuthError } from '../errors.js';
import { type AuthServerConfig } from '../types/auth-server.js';
import { createVerifyJwt } from '../utils/create-verify-jwt.js';

import { TokenVerifier } from './token-verifier.js';

vi.mock('jose', async (importOriginal) => {
  const original = await importOriginal<typeof jose>();
  return {
    ...original,
    createRemoteJWKSet: vi.fn(),
  };
});

vi.mock(import('../utils/create-verify-jwt.js'), async (importOriginal) => {
  const original = await importOriginal();
  return {
    ...original,
    createVerifyJwt: vi.fn(),
  };
});

const secret = new TextEncoder().encode('super-secret-key-for-testing');
const alg = 'HS256';

const createJwt = async (payload: Record<string, unknown>) =>
  new SignJWT(payload)
    .setProtectedHeader({ alg })
    .setIssuedAt()
    .setExpirationTime('1h')
    .sign(secret);

describe('TokenVerifier', () => {
  const authServers: AuthServerConfig[] = [
    {
      type: 'oauth',
      metadata: {
        issuer: 'https://trusted.issuer.com',
        jwksUri: 'https://trusted.issuer.com/.well-known/jwks.json',
        authorizationEndpoint: 'https://trusted.issuer.com/auth',
        tokenEndpoint: 'https://trusted.issuer.com/token',
        responseTypesSupported: ['code'],
      },
    },
    {
      type: 'oauth',
      metadata: {
        issuer: 'https://no-jwks.issuer.com',
        authorizationEndpoint: 'https://no-jwks.issuer.com/auth',
        tokenEndpoint: 'https://no-jwks.issuer.com/token',
        responseTypesSupported: ['code'],
      },
    },
  ];

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  describe('createVerifyJwtFunction', () => {
    it('should throw an MCPAuthBearerAuthError if `iss` is missing from the token payload', async () => {
      const token = await createJwt({
        // Iss is missing
        client_id: 'client12345',
        aud: 'https://trusted.issuer.com',
      });

      const tokenVerifier = new TokenVerifier(authServers);
      await expect(
        tokenVerifier.createVerifyJwtFunction({})(token)
      ).rejects.toThrowErrorMatchingInlineSnapshot(
        '[MCPAuthBearerAuthError: The provided token is not valid or has expired.]'
      );
    });

    it('should throw an MCPAuthBearerAuthError if the issuer of the token is not trusted', async () => {
      const token = await createJwt({
        iss: 'https://untrusted.issuer.com',
        client_id: 'client12345',
        aud: 'https://trusted.issuer.com',
      });

      const tokenVerifier = new TokenVerifier(authServers);
      await expect(
        tokenVerifier.createVerifyJwtFunction({})(token)
      ).rejects.toThrowErrorMatchingInlineSnapshot(
        '[MCPAuthBearerAuthError: The token issuer does not match the expected issuer.]'
      );
    });

    it('should throw an MCPAuthAuthServerError if the authorization server does not have a JWKS URI configured', async () => {
      const token = await createJwt({
        iss: 'https://no-jwks.issuer.com',
        client_id: 'client12345',
        aud: 'https://trusted.issuer.com',
      });

      const tokenVerifier = new TokenVerifier(authServers);
      await expect(
        tokenVerifier.createVerifyJwtFunction({})(token)
      ).rejects.toThrowErrorMatchingInlineSnapshot(
        '[MCPAuthAuthServerError: The server metadata does not contain a JWKS URI, which is required for JWT verification.]'
      );
    });

    it('should call createVerifyJwt with the correct parameters', async () => {
      const verifyJwtMock = vi.fn();
      vi.mocked(createVerifyJwt).mockReturnValue(verifyJwtMock);

      const token = await createJwt({
        iss: 'https://trusted.issuer.com',
        client_id: 'client12345',
        aud: 'https://trusted.issuer.com',
      });

      const tokenVerifier = new TokenVerifier(authServers);
      const verifyJwtFunction = tokenVerifier.createVerifyJwtFunction({
        jwtVerify: {
          clockTolerance: 10,
        },
      });

      await verifyJwtFunction(token);

      expect(jose.createRemoteJWKSet).toHaveBeenCalledWith(
        new URL('https://trusted.issuer.com/.well-known/jwks.json'),
        undefined
      );
      expect(createVerifyJwt).toHaveBeenCalledWith(undefined, {
        clockTolerance: 10,
      });
      expect(verifyJwtMock).toHaveBeenCalledWith(token);
    });
  });

  describe('getJwtIssuerValidator', () => {
    it('should not throw an error for a trusted issuer', () => {
      const tokenVerifier = new TokenVerifier(authServers);
      const validator = tokenVerifier.getJwtIssuerValidator();
      expect(() => {
        validator('https://trusted.issuer.com');
      }).not.toThrow();
    });

    it('should throw an MCPAuthBearerAuthError for an untrusted issuer', () => {
      const tokenVerifier = new TokenVerifier(authServers);
      const validator = tokenVerifier.getJwtIssuerValidator();
      const expectedError = new MCPAuthBearerAuthError('invalid_issuer', {
        expected: authServers.map(({ metadata }) => metadata.issuer).join(', '),
        actual: 'https://untrusted.issuer.com',
      });
      expect(() => {
        validator('https://untrusted.issuer.com');
      }).toThrow(expectedError);
    });
  });
});
