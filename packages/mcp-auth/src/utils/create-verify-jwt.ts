import { type AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { tryThat } from '@silverhand/essentials';
import { jwtVerify, type JWTVerifyGetKey, type JWTVerifyOptions } from 'jose';
import { JOSEError } from 'jose/errors';

import { MCPAuthTokenVerificationError } from '../errors.js';
import { type VerifyAccessTokenFunction } from '../handlers/handle-bearer-auth.js';

const getScopes = (value: unknown): string[] | undefined => {
  if (Array.isArray(value)) {
    return value.filter((item) => typeof item === 'string');
  }
  if (typeof value === 'string') {
    return value.split(' ').filter((item) => item.trim() !== '');
  }
};

/**
 * Creates a function to verify JWT access tokens using the provided key retrieval function
 * and options.
 *
 * @returns A function that verifies JWT access tokens and returns an {@link AuthInfo} object if
 * the token is valid. It requires the JWT to contain the fields `iss`, `client_id`, and `sub` in
 * its payload, and it can optionally contain `scope` or `scopes` fields. The function uses the
 * `jose` library under the hood to perform the JWT verification.
 *
 * @see {@link VerifyAccessTokenFunction} for the type definition of the returned function.
 */
export const createVerifyJwt = (
  /**
   * The function to retrieve the key used to verify the JWT.
   *
   * @see {@link JWTVerifyGetKey} for the type definition of the key retrieval function.
   */
  getKey: JWTVerifyGetKey,
  /**
   * Optional JWT verification options.
   *
   * @see {@link JWTVerifyOptions} for the type definition of the options.
   */
  options?: JWTVerifyOptions
): VerifyAccessTokenFunction => {
  const verifyJwt = async function (token: string): Promise<AuthInfo> {
    const { payload } = await tryThat(jwtVerify(token, getKey, { ...options }), (error) => {
      throw new MCPAuthTokenVerificationError('invalid_token', {
        code: error instanceof JOSEError ? error.code : 'JWT_VERIFICATION_FAILED',
        cause: error,
      });
    });

    if (typeof payload.iss !== 'string' || !payload.iss) {
      throw new MCPAuthTokenVerificationError('invalid_token', {
        cause: 'The JWT payload does not contain the `iss` field or it is malformed.',
      });
    }

    if (typeof payload.sub !== 'string' || !payload.sub) {
      throw new MCPAuthTokenVerificationError('invalid_token', {
        cause: 'The JWT payload does not contain the `sub` field or it is malformed.',
      });
    }
    /*
     * Accept either `client_id` (RFC 9068) or `azp` claim for better compatibility.
     * While `client_id` is required by RFC 9068 for JWT access tokens, many providers
     * (Auth0, Microsoft, Google) may use or support `azp` claim.
     *
     * See: https://github.com/mcp-auth/js/issues/28 for detailed discussion
     */
    const clientId = payload.client_id ?? payload.azp;

    return {
      issuer: payload.iss,
      clientId: typeof clientId === 'string' ? clientId : '',
      scopes: getScopes(payload.scope) ?? getScopes(payload.scopes) ?? [],
      token,
      audience: payload.aud,
      claims: payload,
      expiresAt: payload.exp,
      subject: payload.sub,
    };
  };

  return verifyJwt;
};
