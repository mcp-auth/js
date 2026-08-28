/**
 * Base class for all mcp-auth errors.
 *
 * These errors cover configuration and authorization server discovery failures. Token
 * verification failures are intentionally NOT represented here — `MCPAuth#verifyAccessToken`
 * throws the MCP SDK's `OAuthError` instead, because the SDK bearer-auth helpers only map
 * `OAuthError` to proper `401` challenge responses (anything else becomes a `500`).
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
}

/**
 * Error thrown when there is a configuration issue with mcp-auth, such as an invalid resource
 * identifier or a failed metadata fetch.
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
 * Error thrown when there is an issue with the remote authorization server, such as invalid
 * metadata or a configuration that does not satisfy the MCP authorization specification.
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
