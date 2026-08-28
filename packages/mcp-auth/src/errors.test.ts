import { describe, expect, it } from 'vitest';

import {
  MCPAuthAuthServerError,
  MCPAuthConfigError,
  MCPAuthError,
  type AuthServerErrorCode,
} from './errors.js';

describe('MCPAuthError', () => {
  it('should carry the code and message', () => {
    const error = new MCPAuthError('some_code', 'Some message.');

    expect(error).toBeInstanceOf(Error);
    expect(error.name).toBe('MCPAuthError');
    expect(error.code).toBe('some_code');
    expect(error.message).toBe('Some message.');
  });
});

describe('MCPAuthConfigError', () => {
  it('should be an MCPAuthError with its own name', () => {
    const error = new MCPAuthConfigError('invalid_config', 'Invalid config.');

    expect(error).toBeInstanceOf(MCPAuthError);
    expect(error.name).toBe('MCPAuthConfigError');
  });
});

describe('MCPAuthAuthServerError', () => {
  it('should derive the message from the code and keep the cause', () => {
    const error = new MCPAuthAuthServerError('missing_jwks_uri', { detail: 'no jwks' });

    expect(error).toBeInstanceOf(MCPAuthError);
    expect(error.name).toBe('MCPAuthAuthServerError');
    expect(error.message).toBe(
      'The server metadata does not contain a JWKS URI, which is required for JWT verification.'
    );
    expect(error.cause).toEqual({ detail: 'no jwks' });
  });

  it('should fall back to a generic message for unknown codes', () => {
    const error = new MCPAuthAuthServerError('unknown_code' as AuthServerErrorCode);

    expect(error.message).toBe('An error occurred with the authorization server.');
  });
});
