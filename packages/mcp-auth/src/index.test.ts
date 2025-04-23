import { describe, expect, it, vi } from 'vitest';

import { MCPAuth } from './index.js';

describe('MCPAuth class (init)', () => {
  it('should throw an error if the server configuration is empty or not an object', () => {
    // @ts-expect-error
    expect(() => new MCPAuth({ server: { metadata: null } })).toThrowErrorMatchingInlineSnapshot(
      '[MCPAuthAuthServerError: The server configuration does not match the MCP specification.]'
    );
    // @ts-expect-error
    expect(() => new MCPAuth({ server: { metadata: 123 } })).toThrowErrorMatchingInlineSnapshot(
      '[MCPAuthAuthServerError: The server configuration does not match the MCP specification.]'
    );
  });

  it('should throw an error if the server metadata does not conform to the expected schema', () => {
    expect(
      () =>
        new MCPAuth({
          server: {
            // @ts-expect-error
            metadata: {
              responseTypesSupported: ['code'],
              grantTypesSupported: ['authorization_code'],
              codeChallengeMethodsSupported: ['S256'],
            },
          },
        })
    ).toThrowErrorMatchingInlineSnapshot(
      '[MCPAuthAuthServerError: The server configuration does not match the MCP specification.]'
    );
  });

  it('should not throw an error if the server configuration is valid with warnings', () => {
    const consoleWarnSpy = vi.spyOn(console, 'warn');
    expect(
      () =>
        new MCPAuth({
          server: {
            type: 'oauth',
            metadata: {
              issuer: 'https://example.com',
              authorizationEndpoint: 'https://example.com/oauth/authorize',
              tokenEndpoint: 'https://example.com/oauth/token',
              responseTypesSupported: ['code'],
              grantTypesSupported: ['authorization_code'],
              codeChallengeMethodsSupported: ['S256'],
            },
          },
        })
    ).not.toThrow();
    expect(consoleWarnSpy).toHaveBeenCalledWith(
      'The authorization server configuration has warnings:\n\n  - Dynamic Client Registration (RFC 7591) is not supported by the server.\n'
    );
  });
});

describe('MCPAuth class (bearerAuth)', () => {
  const metadata = Object.freeze({
    issuer: 'https://example.com',
    authorizationEndpoint: 'https://example.com/oauth/authorize',
    tokenEndpoint: 'https://example.com/oauth/token',
    responseTypesSupported: ['code'],
    grantTypesSupported: ['authorization_code'],
    codeChallengeMethodsSupported: ['S256'],
  });

  it('should throw an error if the verification mode is "jwt" but no JWKS url is provided', () => {
    const auth = new MCPAuth({ server: { type: 'oauth', metadata } });

    expect(() => auth.bearerAuth('jwt')).toThrowErrorMatchingInlineSnapshot(
      '[MCPAuthAuthServerError: The server metadata does not contain a JWKS URI, which is required for JWT verification.]'
    );
  });

  it('should throw an error if no verification function is provided', () => {
    const auth = new MCPAuth({ server: { type: 'oauth', metadata } });
    // @ts-expect-error
    expect(() => auth.bearerAuth()).toThrowErrorMatchingInlineSnapshot(
      '[TypeError: `verifyAccessToken` must be a function that takes a token and returns an `AuthInfo` object.]'
    );
  });

  it('should create a bearer auth handler with JWT verification', () => {
    const auth = new MCPAuth({
      server: { type: 'oauth', metadata: { ...metadata, jwksUri: 'https://example.com/jwks' } },
    });
    const handler = auth.bearerAuth('jwt');
    expect(handler).toBeInstanceOf(Function);
    expect(handler.name).toBe('bearerAuthHandler');
  });

  it('should create a bearer auth handler with custom verification function', () => {
    const auth = new MCPAuth({ server: { type: 'oauth', metadata } });
    const verifyAccessToken = vi.fn().mockResolvedValue({ scopes: ['read'] });
    const handler = auth.bearerAuth(verifyAccessToken);
    expect(handler).toBeInstanceOf(Function);
    expect(handler.name).toBe('bearerAuthHandler');
  });
});
