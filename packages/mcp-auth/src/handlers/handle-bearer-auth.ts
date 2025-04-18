import { type IncomingHttpHeaders } from 'node:http';

import { type RequestHandler } from 'express';
import snakecaseKeys from 'snakecase-keys';

import { MCPAuthBearerAuthError } from '../errors';

declare module 'express-serve-static-core' {
  // eslint-disable-next-line @typescript-eslint/consistent-type-definitions
  interface Request {
    auth?: AuthInfo;
  }
}

export type AuthInfo = {
  token: string;
  scopes: string[];
  clientId: string;
  subject?: string;
  audience?: string;
  expiresAt?: number;
  claims?: Record<string, unknown>;
};

export type VerifyAccessTokenFunction = (token: string) => PromiseLike<AuthInfo>;

export type BearerAuthConfig = {
  verifyAccessToken: VerifyAccessTokenFunction;
  issuer: string;
  audience?: string;
  requiredScopes?: string[];
  clockTolerance?: number;
};

const getBearerTokenFromHeaders = (headers: IncomingHttpHeaders): string => {
  const authHeader = headers.authorization;

  if (!authHeader) {
    throw new MCPAuthBearerAuthError('missing_auth_header');
  }

  const [scheme, token, ...rest] = authHeader.split(' ');

  if (scheme?.toLowerCase() !== 'bearer' || rest.length > 0) {
    throw new MCPAuthBearerAuthError('invalid_auth_header_format');
  }

  if (!token) {
    throw new MCPAuthBearerAuthError('missing_bearer_token');
  }

  return token;
};

export const handleBearerAuth = (config: BearerAuthConfig): RequestHandler => {
  return async (request, response, next) => {
    const token = getBearerTokenFromHeaders(request.headers);

    try {
      const authInfo = await config.verifyAccessToken(token);

      if (config.audience && authInfo.audience !== config.audience) {
        throw new MCPAuthBearerAuthError('invalid_audience');
      }

      if (config.requiredScopes) {
        const missingScopes = config.requiredScopes.filter(
          (scope) => !authInfo.scopes.includes(scope)
        );
        if (missingScopes.length > 0) {
          throw new MCPAuthBearerAuthError('missing_required_scopes', {
            missingScopes,
          });
        }
      }

      if (request.auth) {
        console.warn(
          'Request already contains auth info and will be overwritten. Please double-check if this is intended.'
        );
      }

      // eslint-disable-next-line @silverhand/fp/no-mutation
      request.auth = authInfo;
      next();
    } catch (error) {
      if (error instanceof MCPAuthBearerAuthError) {
        response
          .status(error.code === 'missing_required_scopes' ? 403 : 401)
          .json(snakecaseKeys(error.toJson()));
        return;
      }
      console.error('Unexpected error during bearer authentication:', error);
      throw error;
    }
  };
};
