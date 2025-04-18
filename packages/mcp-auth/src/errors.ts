import { condObject } from '@silverhand/essentials';

export class MCPAuthError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'MCPAuthError';
  }
}

export class MCPAuthConfigError extends MCPAuthError {
  constructor(message: string) {
    super(message);
    this.name = 'MCPAuthConfigError';
  }
}

export type MCPAuthBearerAuthErrorCode =
  | 'missing_auth_header'
  | 'invalid_auth_header_format'
  | 'missing_bearer_token'
  | 'invalid_issuer'
  | 'invalid_audience'
  | 'missing_required_scopes'
  | 'invalid_token';

export const bearerAuthErrorDescription: Readonly<Record<MCPAuthBearerAuthErrorCode, string>> =
  Object.freeze({
    missing_auth_header: 'Missing `Authorization` header. Please provide a valid bearer token.',
    invalid_auth_header_format: 'Invalid `Authorization` header format. Expected "Bearer <token>".',
    missing_bearer_token:
      'Missing bearer token in `Authorization` header. Please provide a valid token.',
    invalid_issuer: 'Invalid issuer. The token issuer does not match the expected issuer.',
    invalid_audience: 'Invalid audience. The token audience does not match the expected audience.',
    missing_required_scopes:
      'Missing required scopes. The token does not contain the necessary scopes for this request.',
    invalid_token: 'Invalid token. The provided token is not valid or has expired.',
  });

export type MCPAuthBearerAuthErrorDetails = {
  cause?: unknown;
  uri?: URL;
  missingScopes?: string[];
};

export class MCPAuthBearerAuthError extends MCPAuthError {
  constructor(
    public readonly code: MCPAuthBearerAuthErrorCode,
    public readonly details?: MCPAuthBearerAuthErrorDetails
  ) {
    super(bearerAuthErrorDescription[code] || 'An error occurred during bearer authentication.');
    this.name = 'MCPAuthBearerAuthError';
  }

  toJson(): Record<string, unknown> {
    return condObject({
      errorCode: this.code,
      errorDescription: bearerAuthErrorDescription[this.code],
      errorUri: this.details?.uri?.href,
      missingScopes: this.details?.missingScopes,
    });
  }
}
