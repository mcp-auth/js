import { cond, condObject } from '@silverhand/essentials';

/**
 * Base class for all mcp-auth errors.
 *
 * It provides a standardized way to handle errors related to MCP authentication and authorization.
 */
export class MCPAuthError extends Error {
  name = 'MCPAuthError';

  constructor(
    /**
     * The error code in snake_case format.
     */
    public readonly code: string,
    /**
     * A human-readable description of the error.
     */
    message: string
  ) {
    super(message);
  }

  /**
   * Converts the error to a HTTP response friendly JSON format.
   *
   * @param showCause Whether to include the cause of the error in the JSON response.
   * Defaults to `false`.
   */
  toJson(showCause = false): Record<string, unknown> {
    return condObject({
      error: this.code,
      errorDescription: this.message,
      cause: cond(showCause && this.cause),
    });
  }
}

/**
 * Error thrown when there is a configuration issue with mcp-auth.
 */
export class MCPAuthConfigError extends MCPAuthError {
  name = 'MCPAuthConfigError';
}

export type AuthServerErrorCode =
  | 'invalid_server_metadata'
  | 'invalid_server_config'
  | 'missing_jwks_uri';

export const authServerErrorDescription: Readonly<Record<AuthServerErrorCode, string>> =
  Object.freeze({
    invalid_server_metadata: 'The server metadata is invalid or malformed.',
    invalid_server_config: 'The server configuration does not match the MCP specification.',
    missing_jwks_uri:
      'The server metadata does not contain a JWKS URI, which is required for JWT verification.',
  });

/**
 * Error thrown when there is an issue with the remote authorization server.
 */
export class MCPAuthAuthServerError extends MCPAuthError {
  name = 'MCPAuthAuthServerError';

  constructor(
    public readonly code: AuthServerErrorCode,
    public readonly cause?: unknown
  ) {
    super(
      code,
      authServerErrorDescription[code] || 'An error occurred with the authorization server.'
    );
  }
}

export type BearerAuthErrorCode =
  | 'missing_auth_header'
  | 'invalid_auth_header_format'
  | 'missing_bearer_token'
  | 'invalid_issuer'
  | 'invalid_audience'
  | 'missing_required_scopes'
  | 'invalid_token';

export const bearerAuthErrorDescription: Readonly<Record<BearerAuthErrorCode, string>> =
  Object.freeze({
    missing_auth_header: 'Missing `Authorization` header. Please provide a valid bearer token.',
    invalid_auth_header_format: 'Invalid `Authorization` header format. Expected "Bearer <token>".',
    missing_bearer_token:
      'Missing bearer token in `Authorization` header. Please provide a valid token.',
    invalid_issuer: 'The token issuer does not match the expected issuer.',
    invalid_audience: 'The token audience does not match the expected audience.',
    missing_required_scopes: 'The token does not contain the necessary scopes for this request.',
    invalid_token: 'The provided token is not valid or has expired.',
  });

export type MCPAuthBearerAuthErrorDetails = {
  cause?: unknown;
  uri?: URL;
  missingScopes?: string[];
  expected?: unknown;
  actual?: unknown;
};

/**
 * Error thrown when there is an issue when authenticating with Bearer tokens.
 */
export class MCPAuthBearerAuthError extends MCPAuthError {
  name = 'MCPAuthBearerAuthError';

  constructor(
    public readonly code: BearerAuthErrorCode,
    public readonly cause?: MCPAuthBearerAuthErrorDetails
  ) {
    super(code, bearerAuthErrorDescription[code] || 'An error occurred with the Bearer auth.');
  }

  override toJson(showCause = false): Record<string, unknown> {
    // Matches the OAuth 2.0 error response format at best effort
    return condObject({
      ...super.toJson(showCause),
      errorUri: this.cause?.uri?.href,
      missingScopes: this.cause?.missingScopes,
    });
  }
}

export type MCPAuthJwtVerificationErrorCode = 'invalid_jwt' | 'jwt_verification_failed';

export const jwtVerificationErrorDescription: Readonly<
  Record<MCPAuthJwtVerificationErrorCode, string>
> = Object.freeze({
  invalid_jwt: 'The provided JWT is invalid or malformed.',
  jwt_verification_failed: 'JWT verification failed. The token could not be verified.',
});

/**
 * Error thrown when there is an issue when verifying JWT tokens.
 */
export class MCPAuthJwtVerificationError extends MCPAuthError {
  name = 'MCPAuthJwtVerificationError';

  constructor(
    public readonly code: MCPAuthJwtVerificationErrorCode,
    public readonly cause?: unknown
  ) {
    super(
      code,
      jwtVerificationErrorDescription[code] || 'An error occurred while verifying the JWT.'
    );
  }
}
