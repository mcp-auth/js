import { describe, expect, it, vi } from 'vitest';

import * as authorizationServerHandler from './auth/authorization-server-handler.js';
import * as resourceServerHandler from './auth/resource-server-handler.js';
import { type AuthServerConfig, MCPAuth, MCPAuthAuthServerError } from './index.js';
import { type ResourceServerConfig } from './types/resource-server.js';

const validServerConfig: AuthServerConfig = {
  type: 'oauth',
  metadata: {
    issuer: 'https://example.com',
    authorizationEndpoint: 'https://example.com/oauth/authorize',
    tokenEndpoint: 'https://example.com/oauth/token',
    responseTypesSupported: ['code'],
    grantTypesSupported: ['authorization_code'],
    codeChallengeMethodsSupported: ['S256'],
  },
};

const validResourceConfig: ResourceServerConfig = {
  metadata: {
    resource: 'https://api.example.com',
    authorizationServers: [validServerConfig],
  },
};

describe('MCPAuth class (init)', () => {
  it('should throw an error if both `server` and `protectedResource` are not provided', () => {
    const expectedError = new MCPAuthAuthServerError('invalid_server_config', {
      cause: 'No authorization server or protected resource metadata is provided.',
    });
    // @ts-expect-error
    expect(() => new MCPAuth({})).toThrowError(expectedError);
  });

  it('should instantiate a new instance of `AuthorizationServerHandler` if `server` is provided', () => {
    const authServerHandlerConstructorSpy = vi
      .spyOn(authorizationServerHandler, 'AuthorizationServerHandler')
      .mockImplementationOnce(vi.fn());
    const _ = new MCPAuth({ server: validServerConfig });
    expect(authServerHandlerConstructorSpy).toHaveBeenCalledWith({ server: validServerConfig });
    authServerHandlerConstructorSpy.mockRestore();
  });

  it('should instantiate a new instance of `ResourceServerHandler` if `protectedResource` is provided', () => {
    const resourceServerHandlerConstructorSpy = vi
      .spyOn(resourceServerHandler, 'ResourceServerHandler')
      .mockImplementationOnce(vi.fn());
    const _ = new MCPAuth({ protectedResource: validResourceConfig });
    expect(resourceServerHandlerConstructorSpy).toHaveBeenCalledWith({
      protectedResource: validResourceConfig,
    });
    resourceServerHandlerConstructorSpy.mockRestore();
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

  it('should create a bearer auth handler with JWT and resource in `resource server` mode', () => {
    const auth = new MCPAuth({
      protectedResource: validResourceConfig,
    });
    const handler = auth.bearerAuth('jwt', { resource: validResourceConfig.metadata.resource });
    expect(handler).toBeInstanceOf(Function);
    expect(handler.name).toBe('bearerAuthHandler');
  });

  it('should throw an error when resource is not specified in `resource server` mode', () => {
    const auth = new MCPAuth({
      protectedResource: validResourceConfig,
    });

    const expectedError = new MCPAuthAuthServerError('invalid_server_config', {
      cause:
        'A `resource` must be specified in the `bearerAuth` configuration when using a `protectedResource` configuration.',
    });

    // No resource in the bearerAuth config
    expect(() => auth.bearerAuth('jwt')).toThrowError(expectedError);
  });
});

describe('MCPAuth class (delegatedRouter)', () => {
  it('should call `delegatedRouter` method of the `AuthorizationServerHandler` in authorization server mode', () => {
    const delegatedRouterSpy = vi
      .spyOn(authorizationServerHandler.AuthorizationServerHandler.prototype, 'delegatedRouter')
      .mockImplementationOnce(vi.fn());
    const auth = new MCPAuth({ server: validServerConfig });
    auth.delegatedRouter();
    expect(delegatedRouterSpy).toHaveBeenCalled();
    delegatedRouterSpy.mockRestore();
  });

  it('should call `delegatedRouter` method of the `ResourceServerHandler` in resource server mode', () => {
    const delegatedRouterSpy = vi
      .spyOn(resourceServerHandler.ResourceServerHandler.prototype, 'delegatedRouter')
      .mockImplementationOnce(vi.fn());
    const auth = new MCPAuth({ protectedResource: validResourceConfig });
    auth.delegatedRouter();
    expect(delegatedRouterSpy).toHaveBeenCalled();
    delegatedRouterSpy.mockRestore();
  });
});

describe('MCPAuth class (protectedResourceMetadataRouter)', () => {
  it('should call `protectedResourceMetadataRouter` method of the `AuthorizationServerHandler` in authorization server mode', () => {
    const protectedResourceMetadataRouterSpy = vi
      .spyOn(
        authorizationServerHandler.AuthorizationServerHandler.prototype,
        'protectedResourceMetadataRouter'
      )
      .mockImplementationOnce(vi.fn());
    const auth = new MCPAuth({ server: validServerConfig });
    auth.protectedResourceMetadataRouter();
    expect(protectedResourceMetadataRouterSpy).toHaveBeenCalled();
    protectedResourceMetadataRouterSpy.mockRestore();
  });

  it('should call `protectedResourceMetadataRouter` method of the `ResourceServerHandler` in resource server mode', () => {
    const protectedResourceMetadataRouterSpy = vi
      .spyOn(
        resourceServerHandler.ResourceServerHandler.prototype,
        'protectedResourceMetadataRouter'
      )
      .mockImplementationOnce(vi.fn());
    const auth = new MCPAuth({ protectedResource: validResourceConfig });
    auth.protectedResourceMetadataRouter();
    expect(protectedResourceMetadataRouterSpy).toHaveBeenCalled();
    protectedResourceMetadataRouterSpy.mockRestore();
  });
});
