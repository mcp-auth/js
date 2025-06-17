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
  it('should throw an error if both `server` and `protectedResources` are not provided', () => {
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

  it('should instantiate a new instance of `ResourceServerHandler` if `protectedResources` is provided', () => {
    const resourceServerHandlerConstructorSpy = vi
      .spyOn(resourceServerHandler, 'ResourceServerHandler')
      .mockImplementationOnce(vi.fn());
    const _ = new MCPAuth({ protectedResources: validResourceConfig });
    expect(resourceServerHandlerConstructorSpy).toHaveBeenCalledWith({
      protectedResources: validResourceConfig,
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
      protectedResources: validResourceConfig,
    });
    const handler = auth.bearerAuth('jwt', { resource: validResourceConfig.metadata.resource });
    expect(handler).toBeInstanceOf(Function);
    expect(handler.name).toBe('bearerAuthHandler');
  });

  it('should throw an error when resource is not specified in `resource server` mode', () => {
    const auth = new MCPAuth({
      protectedResources: validResourceConfig,
    });

    const expectedError = new MCPAuthAuthServerError('invalid_server_config', {
      cause:
        'A `resource` must be specified in the `bearerAuth` configuration when using a `protectedResources` configuration.',
    });

    // No resource in the bearerAuth config
    expect(() => auth.bearerAuth('jwt')).toThrowError(expectedError);
  });
});

describe('MCPAuth class (delegatedRouter)', () => {
  it('should throw MCPAuthServerError if called in resource server mode', () => {
    const auth = new MCPAuth({ protectedResources: validResourceConfig });
    const expectedError = new MCPAuthAuthServerError('invalid_server_config', {
      cause: '`delegatedRouter` is not available in `resource server` mode.',
    });
    expect(() => auth.delegatedRouter()).toThrow(expectedError);
  });

  it('should call `createMetadataRouter` method of the `AuthorizationServerHandler` in authorization server mode', () => {
    const delegatedRouterSpy = vi
      .spyOn(
        authorizationServerHandler.AuthorizationServerHandler.prototype,
        'createMetadataRouter'
      )
      .mockImplementationOnce(vi.fn());
    const auth = new MCPAuth({ server: validServerConfig });
    auth.delegatedRouter();
    expect(delegatedRouterSpy).toHaveBeenCalled();
    delegatedRouterSpy.mockRestore();
  });
});

describe('MCPAuth class (protectedResourceMetadataRouter)', () => {
  it('should throw MCPAuthServerError if called in authorization server mode', () => {
    const auth = new MCPAuth({ server: validServerConfig });
    const expectedError = new MCPAuthAuthServerError('invalid_server_config', {
      cause: '`protectedResourceMetadataRouter` is not available in `authorization server` mode.',
    });
    expect(() => auth.protectedResourceMetadataRouter()).toThrow(expectedError);
  });

  it('should call `createMetadataRouter` method of the `ResourceServerHandler` in resource server mode', () => {
    const protectedResourceMetadataRouterSpy = vi
      .spyOn(resourceServerHandler.ResourceServerHandler.prototype, 'createMetadataRouter')
      .mockImplementationOnce(vi.fn());
    const auth = new MCPAuth({ protectedResources: validResourceConfig });
    auth.protectedResourceMetadataRouter();
    expect(protectedResourceMetadataRouterSpy).toHaveBeenCalled();
    protectedResourceMetadataRouterSpy.mockRestore();
  });
});
