import { describe, expect, it } from 'vitest';

import {
  MCPAuthAuthServerError,
  MCPAuthBearerAuthError,
  MCPAuthConfigError,
  MCPAuthError,
  MCPAuthTokenVerificationError,
} from './errors.js';

describe('MCPAuthError', () => {
  it('should have `.toJson()` method with `showCause` parameter', () => {
    const error = new Error('Test error');
    const mcpError = new MCPAuthError('test_code', 'Test message');
    // eslint-disable-next-line @silverhand/fp/no-mutation
    mcpError.cause = error;

    expect(mcpError.toJson()).toEqual({
      error: 'test_code',
      errorDescription: 'Test message',
    });

    expect(mcpError.toJson(true)).toEqual({
      error: 'test_code',
      errorDescription: 'Test message',
      cause: error,
    });
  });

  it('should have `name` and `code` properties', () => {
    const mcpError = new MCPAuthError('test_code', 'Test message');
    expect(mcpError.name).toBe('MCPAuthError');
    expect(mcpError.code).toBe('test_code');
  });
});

describe('MCPAuthConfigError', () => {
  it('should have `name` property', () => {
    const mcpError = new MCPAuthConfigError('test_code', 'Test message');
    expect(mcpError.name).toBe('MCPAuthConfigError');
  });
});

describe('MCPAuthAuthServerError', () => {
  it('should have `name` property', () => {
    const mcpError = new MCPAuthAuthServerError('invalid_server_metadata', 'Test message');
    expect(mcpError.name).toBe('MCPAuthAuthServerError');
  });

  it('should set message based on code', () => {
    const mcpError = new MCPAuthAuthServerError('invalid_server_metadata');
    expect(mcpError.message).toBe('The server metadata is invalid or malformed.');
    expect(mcpError.toJson()).toEqual({
      error: 'invalid_server_metadata',
      errorDescription: 'The server metadata is invalid or malformed.',
    });
  });

  it('should set message to default if code is unknown', () => {
    // @ts-expect-error: Testing unknown code
    const mcpError = new MCPAuthAuthServerError('unknown_code');
    expect(mcpError.message).toBe('An error occurred with the authorization server.');
    expect(mcpError.toJson()).toEqual({
      error: 'unknown_code',
      errorDescription: 'An error occurred with the authorization server.',
    });
  });
});

describe('MCPAuthBearerAuthError', () => {
  it('should have `name` property', () => {
    const mcpError = new MCPAuthBearerAuthError('missing_auth_header');
    expect(mcpError.name).toBe('MCPAuthBearerAuthError');
  });

  it('should set message based on code', () => {
    const mcpError = new MCPAuthBearerAuthError('missing_auth_header');
    expect(mcpError.message).toBe(
      'Missing `Authorization` header. Please provide a valid bearer token.'
    );
    expect(mcpError.toJson()).toEqual({
      error: 'missing_auth_header',
      errorDescription: 'Missing `Authorization` header. Please provide a valid bearer token.',
    });
  });

  it('should set message to default if code is unknown', () => {
    // @ts-expect-error: Testing unknown code
    const mcpError = new MCPAuthBearerAuthError('unknown_code');
    expect(mcpError.message).toBe('An error occurred with the Bearer auth.');
    expect(mcpError.toJson()).toEqual({
      error: 'unknown_code',
      errorDescription: 'An error occurred with the Bearer auth.',
    });
  });

  it('should set `errorUri` and `missingScopes` properties in JSON output', () => {
    const mcpError = new MCPAuthBearerAuthError('missing_required_scopes', {
      uri: new URL('https://example.com/error'),
      missingScopes: ['scope1', 'scope2'],
    });
    expect(mcpError.toJson()).toMatchObject({
      error: 'missing_required_scopes',
      errorUri: 'https://example.com/error',
      missingScopes: ['scope1', 'scope2'],
    });
  });
});

describe('MCPAuthTokenVerificationError', () => {
  it('should have `name` property', () => {
    const mcpError = new MCPAuthTokenVerificationError('invalid_token');
    expect(mcpError.name).toBe('MCPAuthTokenVerificationError');
  });

  it('should set message based on code', () => {
    const mcpError = new MCPAuthTokenVerificationError('invalid_token');
    expect(mcpError.message).toBe('The provided token is invalid or malformed.');
    expect(mcpError.toJson()).toEqual({
      error: 'invalid_token',
      errorDescription: 'The provided token is invalid or malformed.',
    });
  });

  it('should set message to default if code is unknown', () => {
    // @ts-expect-error: Testing unknown code
    const mcpError = new MCPAuthTokenVerificationError('unknown_code');
    expect(mcpError.message).toBe('An error occurred while verifying the token.');
    expect(mcpError.toJson()).toEqual({
      error: 'unknown_code',
      errorDescription: 'An error occurred while verifying the token.',
    });
  });
});
