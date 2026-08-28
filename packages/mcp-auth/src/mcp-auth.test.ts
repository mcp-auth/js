import nock from 'nock';
import { afterEach, describe, expect, it } from 'vitest';

import { MCPAuthConfigError } from './errors.js';
import { MCPAuth } from './mcp-auth.js';
import { matchError } from './test-utils.js';
import { type AuthServerMetadata } from './types.js';

const resource = 'https://api.example.com/mcp';
const issuer = 'https://auth.example.com';

const validMetadata: AuthServerMetadata = Object.freeze({
  issuer,
  authorization_endpoint: `${issuer}/authorize`,
  token_endpoint: `${issuer}/token`,
  jwks_uri: `${issuer}/jwks`,
  response_types_supported: ['code'],
  grant_types_supported: ['authorization_code'],
  code_challenge_methods_supported: ['S256'],
  registration_endpoint: `${issuer}/register`,
});

afterEach(() => {
  nock.cleanAll();
});

describe('MCPAuth constructor', () => {
  it('should create an instance with a valid resolved config', () => {
    expect(
      new MCPAuth({ resource, authorizationServer: { type: 'oidc', metadata: validMetadata } })
    ).toBeInstanceOf(MCPAuth);
  });

  it('should create an instance with a valid discovery config', () => {
    expect(new MCPAuth({ resource, authorizationServer: { issuer, type: 'oidc' } })).toBeInstanceOf(
      MCPAuth
    );
  });

  it('should throw if the resource is missing or not a valid URL', () => {
    expect(
      () => new MCPAuth({ resource: '', authorizationServer: { issuer, type: 'oidc' } })
    ).toThrowError(MCPAuthConfigError);
    expect(
      () => new MCPAuth({ resource: 'not-a-url', authorizationServer: { issuer, type: 'oidc' } })
    ).toThrowError(MCPAuthConfigError);
  });

  it('should throw if the discovery issuer is missing or not a valid URL', () => {
    expect(
      () => new MCPAuth({ resource, authorizationServer: { issuer: '', type: 'oidc' } })
    ).toThrowError(MCPAuthConfigError);
    expect(
      () => new MCPAuth({ resource, authorizationServer: { issuer: 'not-a-url', type: 'oidc' } })
    ).toThrowError(MCPAuthConfigError);
  });

  it('should throw if the resolved metadata is malformed', () => {
    const { token_endpoint: _removed, ...rest } = validMetadata;

    expect(
      () =>
        new MCPAuth({
          resource,

          authorizationServer: { type: 'oidc', metadata: rest as AuthServerMetadata },
        })
    ).toThrowError(matchError('MCPAuthAuthServerError', 'invalid_server_metadata'));
  });

  it('should throw if the resolved metadata does not satisfy the MCP specification', () => {
    const { code_challenge_methods_supported: _removed, ...rest } = validMetadata;

    expect(
      () =>
        new MCPAuth({
          resource,
          authorizationServer: { type: 'oidc', metadata: { ...rest } },
        })
    ).toThrowError(matchError('MCPAuthAuthServerError', 'invalid_server_config'));
  });

  it('should throw if the `serviceDocumentationUrl` is not a valid URL', () => {
    expect(
      () =>
        new MCPAuth({
          resource,
          authorizationServer: { issuer, type: 'oidc' },
          serviceDocumentationUrl: 'not-a-url',
        })
    ).toThrowError(MCPAuthConfigError);
  });

  it('should throw if the `audience` is an empty string', () => {
    expect(
      () => new MCPAuth({ resource, authorizationServer: { issuer, type: 'oidc' }, audience: '' })
    ).toThrowError(MCPAuthConfigError);
  });

  it('should not fetch metadata for a discovery config until it is needed', () => {
    const wellKnown = nock(issuer).get('/.well-known/openid-configuration').reply(200, {});
    void new MCPAuth({ resource, authorizationServer: { issuer, type: 'oidc' } });

    expect(wellKnown.isDone()).toBe(false);
  });
});

describe('MCPAuth resourceMetadataUrl', () => {
  it('should build the RFC 9728 metadata URL with the resource path', () => {
    const mcpAuth = new MCPAuth({ resource, authorizationServer: { issuer, type: 'oidc' } });

    expect(mcpAuth.resourceMetadataUrl).toBe(
      'https://api.example.com/.well-known/oauth-protected-resource/mcp'
    );
  });

  it('should build the RFC 9728 metadata URL for a resource without a path', () => {
    const mcpAuth = new MCPAuth({
      resource: 'https://api.example.com',
      authorizationServer: { issuer, type: 'oidc' },
    });

    expect(mcpAuth.resourceMetadataUrl).toBe(
      'https://api.example.com/.well-known/oauth-protected-resource'
    );
  });
});

describe('MCPAuth getBearerAuthOptions', () => {
  it('should bundle the verifier and the resource metadata URL', () => {
    const mcpAuth = new MCPAuth({ resource, authorizationServer: { issuer, type: 'oidc' } });
    const options = mcpAuth.getBearerAuthOptions();

    expect(options.verifier).toBe(mcpAuth);
    expect(options.resourceMetadataUrl).toBe(mcpAuth.resourceMetadataUrl);
    expect(options).not.toHaveProperty('requiredScopes');
  });

  it('should pass through the required scopes', () => {
    const mcpAuth = new MCPAuth({ resource, authorizationServer: { issuer, type: 'oidc' } });

    expect(mcpAuth.getBearerAuthOptions({ requiredScopes: ['read', 'write'] })).toEqual({
      verifier: mcpAuth,
      resourceMetadataUrl: mcpAuth.resourceMetadataUrl,
      requiredScopes: ['read', 'write'],
    });
  });
});

describe('MCPAuth getAuthMetadataOptions', () => {
  it('should return the metadata verbatim with the configured resource options', async () => {
    const mcpAuth = new MCPAuth({
      resource,
      authorizationServer: { type: 'oidc', metadata: validMetadata },
      scopesSupported: ['read:notes', 'write:notes'],
      resourceName: 'Notes API',
      serviceDocumentationUrl: 'https://docs.example.com',
    });

    await expect(mcpAuth.getAuthMetadataOptions()).resolves.toEqual({
      oauthMetadata: validMetadata,
      resourceServerUrl: new URL(resource),
      scopesSupported: ['read:notes', 'write:notes'],
      resourceName: 'Notes API',
      serviceDocumentationUrl: new URL('https://docs.example.com'),
    });
  });

  it('should omit optional fields that are not configured', async () => {
    const mcpAuth = new MCPAuth({
      resource,
      authorizationServer: { type: 'oidc', metadata: validMetadata },
    });
    const options = await mcpAuth.getAuthMetadataOptions();

    expect(options).toEqual({ oauthMetadata: validMetadata, resourceServerUrl: new URL(resource) });
    expect(Object.keys(options)).toEqual(['oauthMetadata', 'resourceServerUrl']);
  });

  it('should fetch the metadata for a discovery config', async () => {
    const wellKnown = nock(issuer)
      .get('/.well-known/openid-configuration')
      .reply(200, validMetadata);
    const mcpAuth = new MCPAuth({ resource, authorizationServer: { issuer, type: 'oidc' } });

    await expect(mcpAuth.getAuthMetadataOptions()).resolves.toEqual({
      oauthMetadata: validMetadata,
      resourceServerUrl: new URL(resource),
    });
    expect(wellKnown.isDone()).toBe(true);
  });
});
