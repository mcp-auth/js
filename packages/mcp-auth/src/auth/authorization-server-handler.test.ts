import { afterEach, describe, expect, it, vi } from 'vitest';

import { type AuthServerConfig, type AuthServerDiscoveryConfig } from '../types/auth-server.js';
import { validateAuthServer } from '../utils/validate-auth-server.js';

import {
  AuthorizationServerHandler,
  type AuthServerModeConfig,
} from './authorization-server-handler.js';
import { TokenVerifier } from './token-verifier.js';

vi.mock('../utils/validate-auth-server.js');
vi.mock('./token-verifier.js');

describe('AuthorizationServerHandler', () => {
  const mockServerConfig: AuthServerConfig = {
    type: 'oauth',
    metadata: {
      issuer: 'https://example.com',
      authorizationEndpoint: 'https://example.com/auth',
      tokenEndpoint: 'https://example.com/token',
      jwksUri: 'https://example.com/jwks',
      responseTypesSupported: ['code'],
      grantTypesSupported: ['authorization_code'],
      codeChallengeMethodsSupported: ['S256'],
    },
  };

  const mockConfig: AuthServerModeConfig = {
    server: mockServerConfig,
  };

  const discoveryConfig: AuthServerDiscoveryConfig = {
    issuer: 'https://discovery.example.com',
    type: 'oidc',
  };

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('constructor', () => {
    it('should call validateAuthServer with the server config', () => {
      const _ = new AuthorizationServerHandler(mockConfig);
      expect(validateAuthServer).toHaveBeenCalledWith(mockServerConfig);
    });

    it('should create a TokenVerifier instance with the server config', () => {
      const _ = new AuthorizationServerHandler(mockConfig);
      expect(TokenVerifier).toHaveBeenCalledWith([mockServerConfig]);
    });

    it('should log a deprecation warning', () => {
      const consoleWarnSpy = vi.spyOn(console, 'warn');
      const _ = new AuthorizationServerHandler(mockConfig);
      expect(consoleWarnSpy).toHaveBeenCalledWith(
        'The authorization server mode is deprecated. Please use resource server mode instead.'
      );
    });

    it('should work with discovery config', () => {
      const discoveryMockConfig: AuthServerModeConfig = {
        server: discoveryConfig,
      };
      const _ = new AuthorizationServerHandler(discoveryMockConfig);
      expect(validateAuthServer).toHaveBeenCalledWith(discoveryConfig);
      expect(TokenVerifier).toHaveBeenCalledWith([discoveryConfig]);
    });
  });

  describe('createMetadataRouter', () => {
    it('should create a authorization server metadata router', () => {
      const handler = new AuthorizationServerHandler(mockConfig);
      const router = handler.createMetadataRouter();

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

  describe('getTokenVerifier', () => {
    it('should return the TokenVerifier instance', () => {
      const handler = new AuthorizationServerHandler(mockConfig);
      const tokenVerifier = handler.getTokenVerifier({ resource: 'dummy' });
      expect(tokenVerifier).toBeInstanceOf(TokenVerifier);
    });
  });
});
