import { type IncomingHttpHeaders } from 'node:http';

import { type AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
// eslint-disable-next-line unused-imports/no-unused-imports
import { type DEFAULT_REQUEST_TIMEOUT_MSEC } from '@modelcontextprotocol/sdk/shared/protocol.js';
import { condObject } from '@silverhand/essentials';
import { type Response, type RequestHandler } from 'express';
import snakecaseKeys from 'snakecase-keys';

import {
  MCPAuthAuthServerError,
  MCPAuthBearerAuthError,
  MCPAuthConfigError,
  MCPAuthTokenVerificationError,
} from '../errors.js';
import { type MaybePromise } from '../types/promise.js';
import { BearerWWWAuthenticateHeader } from '../utils/bearer-www-authenticate-header.js';

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
     * The issuer of the access token, which is typically the OAuth / OIDC provider that issued
     * the token. This is usually a URL that identifies the authorization server.
     *
     * @see https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1
     * @see https://openid.net/specs/openid-connect-core-1_0.html#IssuerIdentifier
     */
    issuer: string;
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

/**
 * Function type for verifying an access token.
 *
 * This function should throw an {@link MCPAuthTokenVerificationError} if the token is invalid,
 * or return an {@link AuthInfo} object if the token is valid.
 *
 * For example, if you have a JWT verification function, it should at least check the token's
 * signature, validate its expiration, and extract the necessary claims to return an `AuthInfo`
 * object.
 *
 * **Note:** There's no need to verify the following fields in the token, as they will be checked
 * by the handler:
 *
 * - `iss` (issuer)
 * - `aud` (audience)
 * - `scope` (scopes)
 *
 * @param token The access token string to verify.
 * @returns A promise that resolves to an {@link AuthInfo} object or a synchronous value if the
 * token is valid.
 */
export type VerifyAccessTokenFunction = (token: string) => MaybePromise<AuthInfo>;

/**
 * Function type for validating the issuer of the access token.
 *
 * This function should throw an {@link MCPAuthBearerAuthError} with code 'invalid_issuer' if the issuer
 * is not valid. The issuer should be validated against:
 *
 * 1. The authorization servers configured in MCP-Auth's auth server metadata
 * 2. The authorization servers listed in the protected resource's metadata
 *
 * @param issuer The issuer of the access token.
 * @throws {MCPAuthBearerAuthError} When the issuer is not recognized or invalid.
 */
export type ValidateIssuerFunction = (tokenIssuer: string) => void;

export type BearerAuthConfig = {
  /**
   * Function type for verifying an access token.
   *
   * This function should throw an {@link MCPAuthTokenVerificationError} if the token is invalid,
   * or return an {@link AuthInfo} object if the token is valid.
   *
   * @see {@link VerifyAccessTokenFunction} for more details.
   */
  verifyAccessToken: VerifyAccessTokenFunction;
  /**
   * Function for validating the issuer of the access token.
   *
   * @see {@link ValidateIssuerFunction} for more details.
   */
  validateIssuer: ValidateIssuerFunction;
  /**
   * The expected audience of the access token (`aud` claim). This is typically the resource server
   * (API) that the token is intended for. If not provided, the audience check will be skipped.
   *
   * **Note:** If your authorization server does not support Resource Indicators (RFC 8707),
   * you can omit this field since the audience may not be relevant.
   *
   * @see https://datatracker.ietf.org/doc/html/rfc8707
   */
  audience?: string;
  /**
   * An array of required scopes that the access token must have. If the token does not contain
   * all of these scopes, an error will be thrown.
   *
   * **Note:** The handler will check the `scope` claim in the token, which may be a space-
   * separated string or an array of strings, depending on the authorization server's
   * implementation. If the `scope` claim is not present, the handler will check the `scopes` claim
   * if available.
   */
  requiredScopes?: string[];
  /**
   * The URL of the protected resource metadata endpoint. This URL is used in the WWW-Authenticate
   * response header when token validation fails.
   *
   * When provided, it will be included in the WWW-Authenticate header as the `resource_metadata`
   * parameter, which points to the OAuth 2.0 Protected Resource Metadata document.
   *
   * Example:
   * If set to "https://api.example.com/.well-known/oauth-protected-resource",
   * the WWW-Authenticate header will include:
   * ```
   * WWW-Authenticate: Bearer
   *   resource_metadata="https://api.example.com/.well-known/oauth-protected-resource"
   * ```
   */
  protectedResourceMetadataEndpoint?: string;
  /**
   * Whether to show detailed error information in the response. This is useful for debugging
   * during development, but should be disabled in production to avoid leaking sensitive
   * information.
   *
   * @default false
   */
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

const handleError = (
  error: unknown,
  response: Response,
  protectedResourceMetadataEndpoint: string | undefined,
  showErrorDetails = false
): void => {
  const wwwAuthenticateHeader = new BearerWWWAuthenticateHeader();

  if (error instanceof MCPAuthTokenVerificationError || error instanceof MCPAuthBearerAuthError) {
    wwwAuthenticateHeader.setParameter('error', error.code);
    wwwAuthenticateHeader.setParameter('error_description', error.message);
  }

  if (error instanceof MCPAuthTokenVerificationError) {
    wwwAuthenticateHeader.setParameter('resource_metadata', protectedResourceMetadataEndpoint);

    response
      .set(wwwAuthenticateHeader.headerName, wwwAuthenticateHeader.toString())
      .status(401)
      .json(snakecaseKeys(error.toJson(showErrorDetails)));
    return;
  }

  if (error instanceof MCPAuthBearerAuthError) {
    const statusCode = error.code === 'missing_required_scopes' ? 403 : 401;

    if (statusCode === 401) {
      wwwAuthenticateHeader.setParameter('resource_metadata', protectedResourceMetadataEndpoint);
    }

    response
      .set(wwwAuthenticateHeader.headerName, wwwAuthenticateHeader.toString())
      .status(statusCode)
      .json(snakecaseKeys(error.toJson(showErrorDetails)));
    return;
  }

  if (error instanceof MCPAuthAuthServerError || error instanceof MCPAuthConfigError) {
    response.status(500).json(
      snakecaseKeys(
        condObject({
          error: 'server_error',
          error_description: 'An error occurred with the authorization server.',
          cause: showErrorDetails ? error.toJson() : undefined,
        })
      )
    );
    return;
  }

  throw error;
};

/**
 * Creates a middleware function for handling Bearer auth in an Express application.
 *
 * This middleware extracts the Bearer token from the `Authorization` header, verifies it using the
 * provided `verifyAccessToken` function, and checks the issuer, audience, and required scopes.
 *
 * - If the token is valid, it adds the auth information to the `request.auth` property;
 * if not, it responds with an appropriate error message.
 * - If access token verification fails, it responds with a 401 Unauthorized error.
 * - If the token does not have the required scopes, it responds with a 403 Forbidden error.
 * - If unexpected errors occur during the auth process, the middleware will re-throw them.
 *
 * **Note:**  The `request.auth` object will contain extended fields compared to the standard
 * {@link AuthInfo} interface defined in the `@modelcontextprotocol/sdk` module. See the extended
 * interface in this file for details.
 *
 * @param param0 Configuration for the Bearer auth handler.
 * @returns A middleware function for Express that handles Bearer auth.
 * @see {@link BearerAuthConfig} for the configuration options.
 */
export const handleBearerAuth = ({
  verifyAccessToken,
  validateIssuer,
  requiredScopes,
  audience,
  protectedResourceMetadataEndpoint,
  showErrorDetails,
}: BearerAuthConfig): RequestHandler => {
  if (typeof verifyAccessToken !== 'function') {
    throw new TypeError(
      '`verifyAccessToken` must be a function that takes a token and returns an `AuthInfo` object.'
    );
  }

  if (typeof validateIssuer !== 'function') {
    throw new TypeError(
      '`validateIssuer` must be a function that takes an issuer and throws an `MCPAuthBearerAuthError` if the issuer is not valid.'
    );
  }

  const bearerAuthHandler: RequestHandler = async function (request, response, next) {
    try {
      const token = getBearerTokenFromHeaders(request.headers);
      const authInfo = await verifyAccessToken(token);

      validateIssuer(authInfo.issuer);

      if (
        audience &&
        (Array.isArray(authInfo.audience)
          ? !authInfo.audience.includes(audience)
          : authInfo.audience !== audience)
      ) {
        throw new MCPAuthBearerAuthError('invalid_audience', {
          expected: audience,
          actual: authInfo.audience,
        });
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
      console.error('Error during Bearer auth:', error);
      handleError(error, response, protectedResourceMetadataEndpoint, showErrorDetails);
    }
  };

  return bearerAuthHandler;
};
