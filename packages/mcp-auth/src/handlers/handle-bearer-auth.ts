import { type IncomingHttpHeaders } from 'node:http';

import { type AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { condObject } from '@silverhand/essentials';
import { type Response, type RequestHandler } from 'express';
import snakecaseKeys from 'snakecase-keys';

import {
  MCPAuthAuthServerError,
  MCPAuthBearerAuthError,
  MCPAuthConfigError,
  MCPAuthJwtVerificationError,
} from '../errors.js';

declare module '@modelcontextprotocol/sdk/server/auth/types.js' {
  /**
   *
   * **Notes from mcp-auth:**
   *
   * This interface has been extended to include additional fields that are supported by mcp-auth.
   * These fields can be used in the MCP handlers to provide more context about the authenticated
   * identity.
   */
  // eslint-disable-next-line @typescript-eslint/consistent-type-definitions
  interface AuthInfo {
    /**
     *
     * **Notes from mcp-auth:**
     *
     * The raw access token received in the request.
     */
    token: string;
    /**
     *
     * **Notes from mcp-auth:**
     *
     * The client ID which identifies the OAuth client that the token was issued to. This is
     * typically the client ID registered with the OAuth / OIDC provider.
     *
     * Some providers may use "application ID" or similar terms instead of "client ID".
     */
    clientId: string;
    /**
     *
     * **Notes from mcp-auth:**
     *
     * The scopes (permissions) that the access token has been granted. Scopes define what actions
     * the token can perform on behalf of the user or client. Normally, you need to define these
     * scopes in the OAuth / OIDC provider and assign them to the {@link subject} of the token.
     *
     * The provider may support different mechanisms for defining and managing scopes, such as
     * role-based access control (RBAC) or fine-grained permissions.
     */
    scopes: string[];
    expiresAt?: number;
    // ------ Additional fields added by mcp-auth -------
    /**
     * The `sub` (subject) claim of the token, which typically represents the user ID or principal
     * that the token is issued for.
     *
     * @see https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2
     */
    subject?: string;
    /**
     * The `aud` (audience) claim of the token, which indicates the intended recipient(s) of the
     * token.
     *
     * For OAuth / OIDC providers that support Resource Indicators (RFC 8707), this
     * claim can be used to specify the intended Resource Server (API) that the token is meant for.
     *
     * @see https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
     * @see https://datatracker.ietf.org/doc/html/rfc8707
     */
    audience?: string | string[];
    /**
     * The raw claims from the token, which can include any additional information provided by the
     * token issuer.
     */
    claims?: Record<string, unknown>;
  }
}

declare module 'express-serve-static-core' {
  // eslint-disable-next-line @typescript-eslint/consistent-type-definitions
  interface Request {
    auth?: AuthInfo;
  }
}

export type VerifyAccessTokenFunction = (token: string) => PromiseLike<AuthInfo>;

export type BearerAuthConfig = {
  verifyAccessToken: VerifyAccessTokenFunction;
  issuer: string;
  audience?: string;
  requiredScopes?: string[];
  showErrorDetails?: boolean;
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

const handleError = (error: unknown, response: Response, showErrorDetails = false): void => {
  console.error('Error during bearer authentication:', error, showErrorDetails);

  if (error instanceof MCPAuthJwtVerificationError) {
    response.status(401).json(snakecaseKeys(error.toJson(showErrorDetails)));
    return;
  }

  if (error instanceof MCPAuthBearerAuthError) {
    response
      .status(error.code === 'missing_required_scopes' ? 403 : 401)
      .json(snakecaseKeys(error.toJson(showErrorDetails)));
    return;
  }

  if (error instanceof MCPAuthAuthServerError || error instanceof MCPAuthConfigError) {
    console.error('Authorization server error:', error);
    response.status(500).json(
      condObject({
        error: 'server_error',
        error_description: 'An error occurred with the authorization server.',
        cause: showErrorDetails ? error.toJson() : undefined,
      })
    );
    return;
  }

  console.error('Unexpected error during bearer authentication:', error);
  throw error;
};

export const handleBearerAuth = ({
  verifyAccessToken,
  requiredScopes,
  audience,
  showErrorDetails,
}: BearerAuthConfig): RequestHandler => {
  return async (request, response, next) => {
    try {
      const token = getBearerTokenFromHeaders(request.headers);
      const authInfo = await verifyAccessToken(token);

      if (audience && authInfo.audience !== audience) {
        throw new MCPAuthBearerAuthError('invalid_audience');
      }

      if (requiredScopes) {
        const missingScopes = requiredScopes.filter((scope) => !authInfo.scopes.includes(scope));
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
      handleError(error, response, showErrorDetails);
    }
  };
};
