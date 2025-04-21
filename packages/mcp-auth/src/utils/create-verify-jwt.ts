import { tryThat } from '@silverhand/essentials';
import { jwtVerify, type JWTVerifyGetKey, type JWTVerifyOptions } from 'jose';
import { JOSEError } from 'jose/errors';

import { MCPAuthJwtVerificationError } from '../errors.js';
import { type VerifyAccessTokenFunction } from '../handlers/handle-bearer-auth.js';

const getScopes = (value: unknown): string[] | undefined => {
  if (Array.isArray(value)) {
    return value.filter((item) => typeof item === 'string');
  }
  if (typeof value === 'string') {
    return value.split(' ').filter((item) => item.trim() !== '');
  }
};

export const createVerifyJwt =
  (getKey: JWTVerifyGetKey, options?: JWTVerifyOptions): VerifyAccessTokenFunction =>
  async (token) => {
    const { payload } = await tryThat(jwtVerify(token, getKey, { ...options }), (error) => {
      throw new MCPAuthJwtVerificationError('invalid_jwt', {
        code: error instanceof JOSEError ? error.code : 'JWT_VERIFICATION_FAILED',
        cause: error,
      });
    });

    if (typeof payload.client_id !== 'string' || !payload.client_id) {
      throw new MCPAuthJwtVerificationError('invalid_jwt', {
        cause: 'The JWT payload does not contain the `client_id` field or it is malformed.',
      });
    }

    if (typeof payload.sub !== 'string' || !payload.sub) {
      throw new MCPAuthJwtVerificationError('invalid_jwt', {
        cause: 'The JWT payload does not contain the `sub` field or it is malformed.',
      });
    }

    return {
      clientId: payload.client_id,
      scopes: getScopes(payload.scope) ?? getScopes(payload.scopes) ?? [],
      token,
      audience: payload.aud,
      claims: payload,
      expiresAt: payload.exp,
      subject: payload.sub,
    };
  };
