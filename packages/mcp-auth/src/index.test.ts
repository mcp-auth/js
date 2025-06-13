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
      'The authorization server (issuer: `https://example.com`) configuration has warnings:\n\n  - Dynamic Client Registration (RFC 7591) is not supported by the server.\n'
    );
  });

  it('should throw an error if both `server` and `protectedResource` are provided', () => {
    expect(
      // @ts-expect-error
      () => new MCPAuth({ server: {}, protectedResource: {} })
    ).toThrowErrorMatchingInlineSnapshot(
      '[MCPAuthAuthServerError: The server configuration does not match the MCP specification.]'
    );
  });

  it('should throw an error if no `server` or `protectedResource` is provided', () => {
    // @ts-expect-error
    expect(() => new MCPAuth({})).toThrowErrorMatchingInlineSnapshot(
      '[MCPAuthAuthServerError: The server configuration does not match the MCP specification.]'
    );
  });

  it('should initialize successfully with a single protected resource', () => {
    const resource = 'https://api.example.com/notes';
    expect(
      () =>
        new MCPAuth({
          protectedResource: {
            metadata: {
              resource,
              authorizationServers: [
                {
                  type: 'oauth',
                  metadata: {
                    issuer: 'https://auth.example.com',
                    authorizationEndpoint: 'https://auth.example.com/auth',
                    tokenEndpoint: 'https://auth.example.com/token',
                    responseTypesSupported: ['code'],
                    grantTypesSupported: ['authorization_code'],
                    codeChallengeMethodsSupported: ['S256'],
                  },
                },
              ],
            },
          },
        })
    ).not.toThrow();
  });

  it('should initialize successfully with multiple protected resources', () => {
    expect(
      () =>
        new MCPAuth({
          protectedResource: [
            {
              metadata: {
                resource: 'https://api.example.com/notes',
                authorizationServers: [
                  {
                    type: 'oauth',
                    metadata: {
                      issuer: 'https://auth.example.com',
                      authorizationEndpoint: 'https://auth.example.com/auth',
                      tokenEndpoint: 'https://auth.example.com/token',
                      responseTypesSupported: ['code'],
                      grantTypesSupported: ['authorization_code'],
                      codeChallengeMethodsSupported: ['S256'],
                    },
                  },
                ],
              },
            },
            {
              metadata: {
                resource: 'https://api.example.com/photos',
                authorizationServers: [
                  {
                    type: 'oauth',
                    metadata: {
                      issuer: 'https://auth.example.com',
                      authorizationEndpoint: 'https://auth.example.com/auth',
                      tokenEndpoint: 'https://auth.example.com/token',
                      responseTypesSupported: ['code'],
                      grantTypesSupported: ['authorization_code'],
                      codeChallengeMethodsSupported: ['S256'],
                    },
                  },
                ],
              },
            },
          ],
        })
    ).not.toThrow();
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

  it('should create a bearer auth handler with JWT and resource in `protectedResource` mode', () => {
    const resource = 'https://api.example.com/notes';
    const auth = new MCPAuth({
      protectedResource: {
        metadata: {
          resource,
          authorizationServers: [
            {
              type: 'oauth',
              metadata: { ...metadata, jwksUri: 'https://example.com/jwks' },
            },
          ],
        },
      },
    });
    const handler = auth.bearerAuth('jwt', { resource });
    expect(handler).toBeInstanceOf(Function);
    expect(handler.name).toBe('bearerAuthHandler');
  });

  it('should throw an error when resource is not found in `protectedResource` mode', () => {
    const resource = 'https://api.example.com/notes';
    const auth = new MCPAuth({
      protectedResource: {
        metadata: {
          resource,
          authorizationServers: [{ type: 'oauth', metadata }],
        },
      },
    });

    expect(() =>
      auth.bearerAuth('jwt', { resource: 'https://api.example.com/non-existent' })
    ).toThrowErrorMatchingInlineSnapshot(
      '[MCPAuthAuthServerError: The server configuration does not match the MCP specification.]'
    );
  });
});

describe('MCPAuth class (delegatedRouter)', () => {
  const metadata = Object.freeze({
    issuer: 'https://example.com',
    authorizationEndpoint: 'https://example.com/oauth/authorize',
    tokenEndpoint: 'https://example.com/oauth/token',
    responseTypesSupported: ['code'],
    grantTypesSupported: ['authorization_code'],
    codeChallengeMethodsSupported: ['S256'],
  });

  it('should throw an error if not in `server` mode', () => {
    const auth = new MCPAuth({
      protectedResource: {
        metadata: {
          resource: 'foo',
          authorizationServers: [],
        },
      },
    });
    expect(() => auth.delegatedRouter()).toThrowErrorMatchingInlineSnapshot(
      '[MCPAuthAuthServerError: The server configuration does not match the MCP specification.]'
    );
  });

  it('should return a router in `server` mode', () => {
    const auth = new MCPAuth({
      server: {
        type: 'oauth',
        metadata,
      },
    });
    const router = auth.delegatedRouter();
    expect(router).toBeInstanceOf(Function);

    expect(router.stack).toContainEqual(
      expect.objectContaining({
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
        route: expect.objectContaining({
          path: '/.well-known/oauth-authorization-server',
          methods: { get: true },
        }),
      })
    );
  });
});

describe('MCPAuth class (protectedResourceMetadataRouter)', () => {
  const metadata = Object.freeze({
    issuer: 'https://example.com',
    authorizationEndpoint: 'https://example.com/oauth/authorize',
    tokenEndpoint: 'https://example.com/oauth/token',
    responseTypesSupported: ['code'],
    grantTypesSupported: ['authorization_code'],
    codeChallengeMethodsSupported: ['S256'],
  });

  it('should throw an error if not in `protectedResource` mode', () => {
    const auth = new MCPAuth({
      server: {
        type: 'oauth',
        metadata,
      },
    });
    expect(() => auth.protectedResourceMetadataRouter()).toThrowErrorMatchingInlineSnapshot(
      '[MCPAuthAuthServerError: The server configuration does not match the MCP specification.]'
    );
  });

  it('should return a router in `protectedResource` mode', () => {
    const auth = new MCPAuth({
      protectedResource: {
        metadata: {
          resource: 'https://api.example.com',
          scopesSupported: ['read'],
          authorizationServers: [],
        },
      },
    });
    const router = auth.protectedResourceMetadataRouter();
    expect(router).toBeInstanceOf(Function);

    expect(router.stack).toContainEqual(
      expect.objectContaining({
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
        route: expect.objectContaining({
          path: '/.well-known/oauth-protected-resource',
          methods: { get: true },
        }),
      })
    );
  });
});
