import { noop } from '@silverhand/essentials';
import httpMocks from 'node-mocks-http';
import { describe, expect, it, vi } from 'vitest';

import {
  MCPAuthAuthServerError,
  MCPAuthConfigError,
  MCPAuthJwtVerificationError,
} from '../errors.js';

import { handleBearerAuth, type VerifyAccessTokenFunction } from './handle-bearer-auth.js';

describe('handleBearerAuth()', () => {
  it('should return a function', () => {
    expect(
      handleBearerAuth({
        // @ts-expect-error
        verifyAccessToken: noop,
        issuer: 'https://example.com',
        requiredScopes: [],
        audience: undefined,
      })
    ).toBeInstanceOf(Function);
  });

  it('should throw an error if verifyAccessToken is not a function', () => {
    expect(() =>
      handleBearerAuth({
        // @ts-expect-error
        verifyAccessToken: 'not a function',
        issuer: 'https://example.com',
        requiredScopes: [],
        audience: undefined,
      })
    ).toThrowErrorMatchingInlineSnapshot(
      '[TypeError: `verifyAccessToken` must be a function that takes a token and returns an `AuthInfo` object.]'
    );
  });
});

describe('handleBearerAuth() returned function with invalid headers or tokens', () => {
  const issuer = 'https://example.com';
  const requiredScopes = ['read', 'write'];
  const audience = 'test-audience';
  const verifyAccessToken = vi.fn<VerifyAccessTokenFunction>(async (token: string) => {
    if (token === 'valid-token') {
      return { issuer, clientId: 'client-id', scopes: ['read', 'write'], token };
    }
    throw new MCPAuthJwtVerificationError('invalid_jwt');
  });

  const handler = handleBearerAuth({
    verifyAccessToken,
    issuer,
    requiredScopes,
    audience,
  });

  it('should respond with an error if the request does not have a bearer token', async () => {
    const request = httpMocks.createRequest();
    const response = httpMocks.createResponse();
    await handler(request, response, noop);

    expect(response.statusCode).toBe(401);
    expect(response._getJSONData()).toEqual({
      error: 'missing_auth_header',
      error_description: 'Missing `Authorization` header. Please provide a valid bearer token.',
    });
  });

  it('should respond with an error if the bearer token is malformed', async () => {
    const response1 = httpMocks.createResponse();
    await handler(
      httpMocks.createRequest({ headers: { authorization: 'Bearer invalid token format' } }),
      response1,
      noop
    );

    expect(response1.statusCode).toBe(401);
    expect(response1._getJSONData()).toEqual({
      error: 'invalid_auth_header_format',
      error_description: 'Invalid `Authorization` header format. Expected "Bearer <token>".',
    });

    const response2 = httpMocks.createResponse();
    await handler(
      httpMocks.createRequest({ headers: { authorization: 'invalid-header' } }),
      response2,
      noop
    );
    expect(response2.statusCode).toBe(401);
    expect(response2._getJSONData()).toEqual({
      error: 'invalid_auth_header_format',
      error_description: 'Invalid `Authorization` header format. Expected "Bearer <token>".',
    });

    const response3 = httpMocks.createResponse();
    await handler(
      httpMocks.createRequest({ headers: { authorization: 'Bearer' } }),
      response3,
      noop
    );
    expect(response3.statusCode).toBe(401);
    expect(response3._getJSONData()).toEqual({
      error: 'missing_bearer_token',
      error_description:
        'Missing bearer token in `Authorization` header. Please provide a valid token.',
    });
  });

  it('should respond with an error if the bearer token is not valid', async () => {
    const response = httpMocks.createResponse();
    await handler(
      httpMocks.createRequest({ headers: { authorization: 'Bearer invalid-token' } }),
      response,
      noop
    );

    expect(response.statusCode).toBe(401);
    expect(response._getJSONData()).toEqual({
      error: 'invalid_jwt',
      error_description: 'The provided JWT is invalid or malformed.',
    });
    expect(verifyAccessToken).toHaveBeenCalledWith('invalid-token');
  });
});

describe('handleBearerAuth() returned function with invalid fields in the token', () => {
  const issuer = 'https://example.com';
  const requiredScopes = ['read', 'write'];
  const audience = 'test-audience';
  const verifyAccessToken = vi.fn<VerifyAccessTokenFunction>(async (token: string) => {
    if (token === 'valid-token') {
      return { issuer, clientId: 'client-id', scopes: ['read', 'write'], token };
    }
    throw new MCPAuthJwtVerificationError('invalid_jwt');
  });
  const handler = handleBearerAuth({
    verifyAccessToken,
    issuer,
    requiredScopes,
    audience,
  });

  it('should respond with an error if the issuer does not match', async () => {
    const response = httpMocks.createResponse();
    verifyAccessToken.mockImplementationOnce(async (token: string) => {
      if (token === 'valid-token') {
        return {
          issuer: 'https://wrong-issuer.com',
          clientId: 'client-id',
          scopes: ['read', 'write'],
          token,
          audience,
        };
      }
      throw new MCPAuthJwtVerificationError('invalid_jwt');
    });
    await handler(
      httpMocks.createRequest({ headers: { authorization: 'Bearer valid-token' } }),
      response,
      noop
    );

    expect(response.statusCode).toBe(401);
    expect(response._getJSONData()).toEqual({
      error: 'invalid_issuer',
      error_description: 'The token issuer does not match the expected issuer.',
    });
  });

  it('should respond with an error if the audience does not match', async () => {
    const response = httpMocks.createResponse();
    await handler(
      httpMocks.createRequest({ headers: { authorization: 'Bearer valid-token' } }),
      response,
      noop
    );

    expect(response.statusCode).toBe(401);
    expect(response._getJSONData()).toEqual({
      error: 'invalid_audience',
      error_description: 'The token audience does not match the expected audience.',
    });
  });

  it('should respond with an error if the audience does not match (array case)', async () => {
    const response = httpMocks.createResponse();
    verifyAccessToken.mockImplementationOnce(async (token: string) => {
      if (token === 'valid-token') {
        return {
          issuer,
          clientId: 'client-id',
          scopes: ['read', 'write'],
          token,
          audience: ['wrong-audience'],
        };
      }
      throw new MCPAuthJwtVerificationError('invalid_jwt');
    });
    await handler(
      httpMocks.createRequest({ headers: { authorization: 'Bearer valid-token' } }),
      response,
      noop
    );

    expect(response.statusCode).toBe(401);
    expect(response._getJSONData()).toEqual({
      error: 'invalid_audience',
      error_description: 'The token audience does not match the expected audience.',
    });
    expect(verifyAccessToken).toHaveBeenCalledWith('valid-token');
  });

  it('should respond with an error if the required scopes are not present', async () => {
    const response = httpMocks.createResponse();
    verifyAccessToken.mockImplementationOnce(async (token: string) => {
      if (token === 'valid-token') {
        return { issuer, clientId: 'client-id', scopes: ['read'], token, audience };
      }
      throw new MCPAuthJwtVerificationError('invalid_jwt');
    });
    await handler(
      httpMocks.createRequest({ headers: { authorization: 'Bearer valid-token' } }),
      response,
      noop
    );

    expect(response.statusCode).toBe(403);
    expect(response._getJSONData()).toEqual({
      error: 'missing_required_scopes',
      error_description: 'The token does not contain the necessary scopes for this request.',
      missing_scopes: ['write'],
    });
  });
});

describe('handleBearerAuth() returned function with valid token', () => {
  const issuer = 'https://example.com';
  const requiredScopes = ['read', 'write'];
  const audience = 'test-audience';
  const verifyAccessToken = vi.fn<VerifyAccessTokenFunction>(async (token: string) => {
    if (token === 'valid-token') {
      return { issuer, clientId: 'client-id', scopes: requiredScopes, token, audience };
    }
    throw new MCPAuthJwtVerificationError('invalid_jwt');
  });
  const handler = handleBearerAuth({
    verifyAccessToken,
    issuer,
    requiredScopes,
    audience,
  });

  it('should call next() if the token is valid and has the correct audience and scopes', async () => {
    const request = httpMocks.createRequest({
      headers: { authorization: 'Bearer valid-token' },
    });
    const response = httpMocks.createResponse();
    const next = vi.fn();

    await handler(request, response, next);

    expect(next).toHaveBeenCalled();
    expect(response.statusCode).toBe(200); // Default status code for successful auth
  });

  it('should override the existing `auth` property on the request object', async () => {
    const request = httpMocks.createRequest({
      headers: { authorization: 'Bearer valid-token' },
      auth: { clientId: 'old-client-id', scopes: ['old-scope'] },
    });
    const response = httpMocks.createResponse();
    const next = vi.fn();
    await handler(request, response, next);
    expect(request.auth).toEqual({
      issuer,
      clientId: 'client-id',
      scopes: ['read', 'write'],
      token: 'valid-token',
      audience: 'test-audience',
    });
    expect(next).toHaveBeenCalled();
    expect(response.statusCode).toBe(200); // Default status code for successful auth
  });
});

describe('handleBearerAuth() returned function with error handling', () => {
  it('should handle `MCPAuthAuthServerError` and `MCPAuthConfigError`', async () => {
    // Test `MCPAuthAuthServerError` with `showErrorDetails` enabled
    const verifyAccessToken = vi.fn<VerifyAccessTokenFunction>(async () => {
      throw new MCPAuthAuthServerError('invalid_server_config', {
        cause: new Error('Server configuration is invalid'),
      });
    });
    const handler = handleBearerAuth({
      verifyAccessToken,
      issuer: 'https://example.com',
      requiredScopes: [],
      audience: undefined,
      showErrorDetails: true,
    });
    const request = httpMocks.createRequest({
      headers: { authorization: 'Bearer valid-token' },
    });
    const response = httpMocks.createResponse();
    await handler(request, response, noop);
    expect(response.statusCode).toBe(500);
    expect(response._getJSONData()).toEqual({
      error: 'server_error',
      error_description: 'An error occurred with the authorization server.',
      cause: {
        error: 'invalid_server_config',
        error_description: 'The server configuration does not match the MCP specification.',
      },
    });

    // Test `MCPAuthConfigError`
    const verifyAccessTokenConfigError = vi.fn<VerifyAccessTokenFunction>(async () => {
      throw new MCPAuthConfigError('invalid_config', 'Configuration is invalid');
    });

    const configErrorHandler = handleBearerAuth({
      verifyAccessToken: verifyAccessTokenConfigError,
      issuer: 'https://example.com',
      requiredScopes: [],
      audience: undefined,
    });
    const configErrorRequest = httpMocks.createRequest({
      headers: { authorization: 'Bearer valid-token' },
    });
    const configErrorResponse = httpMocks.createResponse();
    await configErrorHandler(configErrorRequest, configErrorResponse, noop);
    expect(configErrorResponse.statusCode).toBe(500);
    expect(configErrorResponse._getJSONData()).toEqual({
      error: 'server_error',
      error_description: 'An error occurred with the authorization server.',
    });
  });

  it('should throw for unexpected errors', async () => {
    const verifyAccessToken = vi.fn<VerifyAccessTokenFunction>(async () => {
      throw new Error('Unexpected error');
    });
    const handler = handleBearerAuth({
      verifyAccessToken,
      issuer: 'https://example.com',
      requiredScopes: [],
      audience: undefined,
    });
    const request = httpMocks.createRequest({
      headers: { authorization: 'Bearer valid-token' },
    });
    const response = httpMocks.createResponse();
    await expect(handler(request, response, noop)).rejects.toThrow('Unexpected error');
  });

  it('should show error details for `MCPAuthBearerAuthError`', async () => {
    const issuer = 'https://example.com';
    const requiredScopes = ['read', 'write'];
    const audience = 'test-audience';
    const verifyAccessToken = vi.fn<VerifyAccessTokenFunction>(async (token: string) => {
      if (token === 'valid-token') {
        return {
          issuer: issuer + '1',
          clientId: 'client-id',
          scopes: requiredScopes,
          token,
          audience,
        };
      }
      throw new MCPAuthJwtVerificationError('invalid_jwt');
    });
    const handler = handleBearerAuth({
      verifyAccessToken,
      issuer,
      requiredScopes,
      audience,
      showErrorDetails: true,
    });

    const request = httpMocks.createRequest({ headers: { authorization: 'Bearer valid-token' } });
    const response = httpMocks.createResponse();
    await handler(request, response, noop);
    expect(response.statusCode).toBe(401);
    expect(response._getJSONData()).toEqual({
      error: 'invalid_issuer',
      error_description: 'The token issuer does not match the expected issuer.',
      cause: {
        expected: issuer,
        actual: issuer + '1',
      },
    });
    expect(verifyAccessToken).toHaveBeenCalledWith('valid-token');
  });
});
