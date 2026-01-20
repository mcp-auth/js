import { describe, expect, it } from 'vitest';

import { type ResourceServerConfig } from '../types/resource-server.js';

import { transpileResourceMetadata } from './transpile-resource-metadata.js';

describe('transpileResourceMetadata', () => {
  it('should transpile resource metadata to standard format', () => {
    const configMetadata: ResourceServerConfig['metadata'] = {
      resource: 'https://api.example.com',
      authorizationServers: [
        {
          type: 'oidc',
          metadata: {
            issuer: 'https://auth.example.com',
            authorizationEndpoint: 'https://auth.example.com/auth',
            tokenEndpoint: 'https://auth.example.com/token',
            responseTypesSupported: ['code'],
          },
        },
        {
          type: 'oidc',
          metadata: {
            issuer: 'https://another-auth.example.com',
            authorizationEndpoint: 'https://another-auth.example.com/auth',
            tokenEndpoint: 'https://another-auth.example.com/token',
            responseTypesSupported: ['code'],
          },
        },
      ],
      scopesSupported: ['read', 'write'],
    };

    const standardMetadata = transpileResourceMetadata(configMetadata);

    expect(standardMetadata).toEqual({
      resource: 'https://api.example.com',
      authorizationServers: ['https://auth.example.com', 'https://another-auth.example.com'],
      scopesSupported: ['read', 'write'],
    });
  });

  it('should handle metadata with no authorization servers', () => {
    const configMetadata: ResourceServerConfig['metadata'] = {
      resource: 'https://api.example.com',
      scopesSupported: ['read', 'write'],
    };

    const standardMetadata = transpileResourceMetadata(configMetadata);

    expect(standardMetadata).toEqual({
      resource: 'https://api.example.com',
      scopesSupported: ['read', 'write'],
    });
  });

  it('should handle metadata with an empty authorization servers array', () => {
    const configMetadata: ResourceServerConfig['metadata'] = {
      resource: 'https://api.example.com',
      authorizationServers: [],
      scopesSupported: ['read', 'write'],
    };

    const standardMetadata = transpileResourceMetadata(configMetadata);

    expect(standardMetadata).toEqual({
      resource: 'https://api.example.com',
      scopesSupported: ['read', 'write'],
    });
  });

  it('should handle discovery config (issuer + type only)', () => {
    const configMetadata: ResourceServerConfig['metadata'] = {
      resource: 'https://api.example.com',
      authorizationServers: [
        { issuer: 'https://auth.example.com', type: 'oidc' },
        { issuer: 'https://another-auth.example.com', type: 'oauth' },
      ],
      scopesSupported: ['read', 'write'],
    };

    const standardMetadata = transpileResourceMetadata(configMetadata);

    expect(standardMetadata).toEqual({
      resource: 'https://api.example.com',
      authorizationServers: ['https://auth.example.com', 'https://another-auth.example.com'],
      scopesSupported: ['read', 'write'],
    });
  });

  it('should handle mixed resolved and discovery configs', () => {
    const configMetadata: ResourceServerConfig['metadata'] = {
      resource: 'https://api.example.com',
      authorizationServers: [
        // Resolved config
        {
          type: 'oidc',
          metadata: {
            issuer: 'https://auth.example.com',
            authorizationEndpoint: 'https://auth.example.com/auth',
            tokenEndpoint: 'https://auth.example.com/token',
            responseTypesSupported: ['code'],
          },
        },
        // Discovery config
        { issuer: 'https://another-auth.example.com', type: 'oauth' },
      ],
      scopesSupported: ['read', 'write'],
    };

    const standardMetadata = transpileResourceMetadata(configMetadata);

    expect(standardMetadata).toEqual({
      resource: 'https://api.example.com',
      authorizationServers: ['https://auth.example.com', 'https://another-auth.example.com'],
      scopesSupported: ['read', 'write'],
    });
  });
});
