import { afterEach, describe, expect, it, vi, type Mock } from 'vitest';

import { MCPAuthAuthServerError } from '../errors.js';
import { type AuthServerConfig } from '../types/auth-server.js';
import { type ResourceServerConfig } from '../types/resource-server.js';
import { validateAuthServer } from '../utils/validate-auth-server.js';

import { ResourceServerHandler, type ResourceServerModeConfig } from './resource-server-handler.js';
import { TokenVerifier } from './token-verifier.js';

vi.mock('../utils/validate-auth-server.js');
vi.mock('./token-verifier.js');

const authServer1: AuthServerConfig = {
  metadata: {
    issuer: 'https://auth1.example.com',
    authorizationEndpoint: 'https://auth1.example.com/oauth/authorize',
    tokenEndpoint: 'https://auth1.example.com/oauth/token',
    jwksUri: 'https://auth1.example.com/oauth/jwks',
    responseTypesSupported: ['code'],
    grantTypesSupported: ['authorization_code'],
    codeChallengeMethodsSupported: ['S256'],
  },
  type: 'oauth',
};

const authServer2: AuthServerConfig = {
  type: 'oauth',
  metadata: {
    issuer: 'https://auth2.example.com',
    authorizationEndpoint: 'https://auth2.example.com/oauth/authorize',
    tokenEndpoint: 'https://auth2.example.com/oauth/token',
    jwksUri: 'https://auth2.example.com/oauth/jwks',
    responseTypesSupported: ['code'],
    grantTypesSupported: ['authorization_code'],
    codeChallengeMethodsSupported: ['S256'],
  },
};

const resourceServerConfig1: ResourceServerConfig = {
  metadata: {
    resource: 'https://api.example.com/resource1',
    authorizationServers: [authServer1],
    scopesSupported: ['read:resource1', 'write:resource1'],
  },
};

const resourceServerConfig2: ResourceServerConfig = {
  metadata: {
    resource: 'https://api.example.com/resource2',
    authorizationServers: [authServer2],
    scopesSupported: ['read:resource2', 'write:resource2'],
  },
};

describe('ResourceServerHandler', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('constructor', () => {
    it('should throw an error for duplicate resource identifiers', () => {
      const mockConfig: ResourceServerModeConfig = {
        protectedResource: [resourceServerConfig1, resourceServerConfig1],
      };
      const expectedError = new MCPAuthAuthServerError('invalid_server_config', {
        cause: `The resource metadata (\`${resourceServerConfig1.metadata.resource}\`) is duplicated.`,
      });
      expect(() => new ResourceServerHandler(mockConfig)).toThrow(expectedError);
    });

    it('should throw an error for duplicate authorization servers for a single resource', () => {
      const resourceWithDuplicatedAuthServer: ResourceServerConfig = {
        metadata: {
          resource: 'https://api.example.com/resource3',
          authorizationServers: [authServer1, authServer1],
        },
      };
      const mockConfig: ResourceServerModeConfig = {
        protectedResource: resourceWithDuplicatedAuthServer,
      };
      const expectedError = new MCPAuthAuthServerError('invalid_server_config', {
        cause: `The authorization server (\`${authServer1.metadata.issuer}\`) for resource \`https://api.example.com/resource3\` is duplicated.`,
      });
      expect(() => new ResourceServerHandler(mockConfig)).toThrow(expectedError);
    });

    it('should validate each authorization server and create a TokenVerifier for each resource', () => {
      const mockConfig: ResourceServerModeConfig = {
        protectedResource: [resourceServerConfig1, resourceServerConfig2],
      };
      const _ = new ResourceServerHandler(mockConfig);

      // Validation calls
      expect(validateAuthServer).toHaveBeenCalledWith(authServer1);
      expect(validateAuthServer).toHaveBeenCalledWith(authServer2);
      expect(validateAuthServer).toHaveBeenCalledTimes(2);

      // TokenVerifier calls for each resource
      expect(TokenVerifier).toHaveBeenCalledWith([authServer1]);
      expect(TokenVerifier).toHaveBeenCalledWith([authServer2]);
      expect(TokenVerifier).toHaveBeenCalledTimes(2);
    });

    it('should not throw for duplicate authorization servers across different resources', () => {
      const resourceServerConfig3: ResourceServerConfig = {
        metadata: {
          resource: 'https://api.example.com/resource3',
          authorizationServers: [authServer1], // Uses authServer1 again
        },
      };
      const mockConfig: ResourceServerModeConfig = {
        protectedResource: [resourceServerConfig1, resourceServerConfig3],
      };

      expect(() => new ResourceServerHandler(mockConfig)).not.toThrow();
      expect(validateAuthServer).toHaveBeenCalledTimes(2);
      expect(TokenVerifier).toHaveBeenCalledTimes(2);
    });
  });

  describe('delegatedRouter', () => {
    it('should throw MCPAuthAuthServerError', () => {
      const handler = new ResourceServerHandler({
        protectedResource: resourceServerConfig1,
      });
      const expectedError = new MCPAuthAuthServerError('invalid_server_config', {
        cause: '`delegatedRouter` is not available in `resource server` mode.',
      });
      expect(() => handler.delegatedRouter()).toThrow(expectedError);
    });
  });

  describe('protectedResourceMetadataRouter', () => {
    it('should create a router with metadata for a single resource', () => {
      const handler = new ResourceServerHandler({
        protectedResource: resourceServerConfig1,
      });
      const router = handler.protectedResourceMetadataRouter();
      const resourcePath = new URL(resourceServerConfig1.metadata.resource).pathname;

      expect(router.stack).toContainEqual(
        expect.objectContaining({
          // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
          route: expect.objectContaining({
            path: `/.well-known/oauth-protected-resource${resourcePath}`,
            methods: { get: true },
          }),
        })
      );
    });

    it('should create a router with metadata for multiple resources', () => {
      const handler = new ResourceServerHandler({
        protectedResource: [resourceServerConfig1, resourceServerConfig2],
      });
      const router = handler.protectedResourceMetadataRouter();
      const resourcePath1 = new URL(resourceServerConfig1.metadata.resource).pathname;
      const resourcePath2 = new URL(resourceServerConfig2.metadata.resource).pathname;

      expect(router.stack).toContainEqual(
        expect.objectContaining({
          // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
          route: expect.objectContaining({
            path: `/.well-known/oauth-protected-resource${resourcePath1}`,
            methods: { get: true },
          }),
        })
      );
      expect(router.stack).toContainEqual(
        expect.objectContaining({
          // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
          route: expect.objectContaining({
            path: `/.well-known/oauth-protected-resource${resourcePath2}`,
            methods: { get: true },
          }),
        })
      );
    });
  });

  describe('getTokenVerifier', () => {
    it('should throw an error if resource is not specified', () => {
      const handler = new ResourceServerHandler({
        protectedResource: resourceServerConfig1,
      });
      const expectedError = new MCPAuthAuthServerError('invalid_server_config', {
        cause:
          'A `resource` must be specified in the `bearerAuth` configuration when using a `protectedResource` configuration.',
      });
      expect(() => handler.getTokenVerifier({})).toThrow(expectedError);
    });

    it('should throw an error if resource is not found', () => {
      const handler = new ResourceServerHandler({
        protectedResource: [resourceServerConfig1, resourceServerConfig2],
      });
      const unknownResource = 'https://api.example.com/unknown';
      const expectedError = new MCPAuthAuthServerError('invalid_server_config', {
        cause: `No token verifier found for the specified resource: \`${unknownResource}\`. Please ensure that this resource is correctly configured in the \`protectedResource\` array in the MCPAuth constructor.`,
      });
      expect(() => handler.getTokenVerifier({ resource: unknownResource })).toThrow(expectedError);
    });

    it('should return a TokenVerifier instance for a specific resource', () => {
      const handler = new ResourceServerHandler({
        protectedResource: [resourceServerConfig1, resourceServerConfig2],
      });
      /**
       * The constructor was called twice, creating two mock verifier instances.
       * The first instance corresponds to resourceServerConfig1.
       */
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      const verifierForResource1 = (TokenVerifier as Mock).mock.results[0]!.value;
      const verifier = handler.getTokenVerifier({
        resource: resourceServerConfig1.metadata.resource,
      });
      expect(verifier).toBe(verifierForResource1);
    });
  });
});
