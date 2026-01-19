import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  type AuthServerConfig,
  type AuthServerDiscoveryConfig,
  type ResolvedAuthServerConfig,
} from '../types/auth-server.js';
import { type CamelCaseAuthorizationServerMetadata } from '../types/oauth.js';
import { fetchServerConfig } from '../utils/fetch-server-config.js';
import { validateResolvedAuthServer } from '../utils/validate-auth-server.js';

import { AuthServerMetadataCache } from './auth-server-metadata-cache.js';

vi.mock('../utils/fetch-server-config.js');
vi.mock('../utils/validate-auth-server.js');

const mockMetadata: CamelCaseAuthorizationServerMetadata = {
  issuer: 'https://auth.example.com',
  authorizationEndpoint: 'https://auth.example.com/auth',
  tokenEndpoint: 'https://auth.example.com/token',
  jwksUri: 'https://auth.example.com/jwks',
  responseTypesSupported: ['code'],
  grantTypesSupported: ['authorization_code'],
  codeChallengeMethodsSupported: ['S256'],
};

const resolvedConfig: ResolvedAuthServerConfig = {
  type: 'oidc',
  metadata: mockMetadata,
};

const discoveryConfig: AuthServerDiscoveryConfig = {
  issuer: 'https://auth.example.com',
  type: 'oidc',
};

describe('AuthServerMetadataCache', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('getMetadata', () => {
    it('should return metadata directly for resolved config', async () => {
      const cache = new AuthServerMetadataCache();
      const result = await cache.getMetadata(resolvedConfig);

      expect(result).toBe(resolvedConfig.metadata);
      expect(fetchServerConfig).not.toHaveBeenCalled();
    });

    it('should fetch metadata for discovery config', async () => {
      vi.mocked(fetchServerConfig).mockResolvedValue(resolvedConfig);

      const cache = new AuthServerMetadataCache();
      const result = await cache.getMetadata(discoveryConfig);

      expect(fetchServerConfig).toHaveBeenCalledWith(discoveryConfig.issuer, {
        type: discoveryConfig.type,
      });
      expect(validateResolvedAuthServer).toHaveBeenCalledWith(resolvedConfig);
      expect(result).toEqual(mockMetadata);
    });

    it('should cache fetched metadata and return cached value on subsequent calls', async () => {
      vi.mocked(fetchServerConfig).mockResolvedValue(resolvedConfig);

      const cache = new AuthServerMetadataCache();

      // First call - should fetch
      const result1 = await cache.getMetadata(discoveryConfig);
      expect(fetchServerConfig).toHaveBeenCalledTimes(1);

      // Second call - should return cached
      const result2 = await cache.getMetadata(discoveryConfig);
      expect(fetchServerConfig).toHaveBeenCalledTimes(1); // Still 1, not 2

      expect(result1).toEqual(mockMetadata);
      expect(result2).toEqual(mockMetadata);
    });

    it('should share the same promise for concurrent requests', async () => {
      // eslint-disable-next-line @silverhand/fp/no-let
      let resolvePromise: (value: ResolvedAuthServerConfig) => void;
      const delayedPromise = new Promise<ResolvedAuthServerConfig>((resolve) => {
        // eslint-disable-next-line @silverhand/fp/no-mutation
        resolvePromise = resolve;
      });
      vi.mocked(fetchServerConfig).mockReturnValue(delayedPromise);

      const cache = new AuthServerMetadataCache();

      // Start two concurrent requests
      const promise1 = cache.getMetadata(discoveryConfig);
      const promise2 = cache.getMetadata(discoveryConfig);

      // Should only call fetch once
      expect(fetchServerConfig).toHaveBeenCalledTimes(1);

      // Resolve the promise
      resolvePromise!(resolvedConfig);

      const [result1, result2] = await Promise.all([promise1, promise2]);

      expect(result1).toEqual(mockMetadata);
      expect(result2).toEqual(mockMetadata);
    });

    it('should validate fetched metadata', async () => {
      vi.mocked(fetchServerConfig).mockResolvedValue(resolvedConfig);

      const cache = new AuthServerMetadataCache();
      await cache.getMetadata(discoveryConfig);

      expect(validateResolvedAuthServer).toHaveBeenCalledWith(resolvedConfig);
    });

    it('should propagate validation errors', async () => {
      const validationError = new Error('Invalid metadata');
      vi.mocked(fetchServerConfig).mockResolvedValue(resolvedConfig);
      vi.mocked(validateResolvedAuthServer).mockImplementation(() => {
        throw validationError;
      });

      const cache = new AuthServerMetadataCache();

      await expect(cache.getMetadata(discoveryConfig)).rejects.toThrow(validationError);
    });

    it('should propagate fetch errors', async () => {
      const fetchError = new Error('Network error');
      vi.mocked(fetchServerConfig).mockRejectedValue(fetchError);

      const cache = new AuthServerMetadataCache();

      await expect(cache.getMetadata(discoveryConfig)).rejects.toThrow(fetchError);
    });

    it('should clear promise cache after fetch completes (success)', async () => {
      vi.mocked(fetchServerConfig).mockResolvedValue(resolvedConfig);

      const cache = new AuthServerMetadataCache();
      await cache.getMetadata(discoveryConfig);

      // After completion, promise cache should be cleared but value cache should have the result
      // A new discovery config with different issuer should trigger a new fetch
      const anotherDiscoveryConfig: AuthServerConfig = {
        issuer: 'https://another-auth.example.com',
        type: 'oidc',
      };
      const anotherMetadata: CamelCaseAuthorizationServerMetadata = {
        ...mockMetadata,
        issuer: 'https://another-auth.example.com',
      };
      vi.mocked(fetchServerConfig).mockResolvedValue({
        type: 'oidc',
        metadata: anotherMetadata,
      });

      const result = await cache.getMetadata(anotherDiscoveryConfig);
      expect(fetchServerConfig).toHaveBeenCalledTimes(2);
      expect(result).toEqual(anotherMetadata);
    });

    it('should clear promise cache after fetch fails', async () => {
      const fetchError = new Error('Network error');
      vi.mocked(fetchServerConfig).mockRejectedValueOnce(fetchError);

      const cache = new AuthServerMetadataCache();

      // First call fails
      await expect(cache.getMetadata(discoveryConfig)).rejects.toThrow(fetchError);

      // Second call should retry (promise cache was cleared)
      vi.mocked(fetchServerConfig).mockResolvedValue(resolvedConfig);
      const result = await cache.getMetadata(discoveryConfig);

      expect(fetchServerConfig).toHaveBeenCalledTimes(2);
      expect(result).toEqual(mockMetadata);
    });
  });
});
