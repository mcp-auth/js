import { afterEach, describe, expect, it, vi } from 'vitest';

import { AuthServerContext } from './auth-server-context.js';
import { MCPAuthAuthServerError } from './errors.js';
import { fetchServerConfig } from './fetch-server-config.js';
import { matchError } from './test-utils.js';
import {
  type AuthServerDiscoveryConfig,
  type AuthServerMetadata,
  type ResolvedAuthServerConfig,
} from './types.js';
import { validateResolvedMetadata } from './validate-auth-server.js';

vi.mock('./fetch-server-config.js');
vi.mock('./validate-auth-server.js');

const mockMetadata: AuthServerMetadata = Object.freeze({
  issuer: 'https://auth.example.com',
  authorization_endpoint: 'https://auth.example.com/authorize',
  token_endpoint: 'https://auth.example.com/token',
  jwks_uri: 'https://auth.example.com/jwks',
  response_types_supported: ['code'],
  grant_types_supported: ['authorization_code'],
  code_challenge_methods_supported: ['S256'],
});

const resolvedConfig: ResolvedAuthServerConfig = {
  type: 'oidc',
  metadata: mockMetadata,
};

const discoveryConfig: AuthServerDiscoveryConfig = {
  issuer: 'https://auth.example.com',
  type: 'oidc',
};

describe('AuthServerContext', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('issuer', () => {
    it('should return the issuer without fetching metadata', () => {
      expect(new AuthServerContext(resolvedConfig).issuer).toBe('https://auth.example.com');
      expect(new AuthServerContext(discoveryConfig).issuer).toBe('https://auth.example.com');
      expect(fetchServerConfig).not.toHaveBeenCalled();
    });
  });

  describe('getMetadata', () => {
    it('should return metadata directly for a resolved config', async () => {
      const context = new AuthServerContext(resolvedConfig);

      await expect(context.getMetadata()).resolves.toBe(mockMetadata);
      expect(fetchServerConfig).not.toHaveBeenCalled();
    });

    it('should fetch and validate metadata for a discovery config', async () => {
      vi.mocked(fetchServerConfig).mockResolvedValue(resolvedConfig);

      const context = new AuthServerContext(discoveryConfig);

      await expect(context.getMetadata()).resolves.toBe(mockMetadata);
      expect(fetchServerConfig).toHaveBeenCalledWith(discoveryConfig.issuer, {
        type: discoveryConfig.type,
      });
      expect(validateResolvedMetadata).toHaveBeenCalledWith(mockMetadata);
    });

    it('should cache the fetched metadata across calls', async () => {
      vi.mocked(fetchServerConfig).mockResolvedValue(resolvedConfig);

      const context = new AuthServerContext(discoveryConfig);
      await context.getMetadata();
      await context.getMetadata();

      expect(fetchServerConfig).toHaveBeenCalledTimes(1);
    });

    it('should share a single fetch for concurrent calls', async () => {
      vi.mocked(fetchServerConfig).mockResolvedValue(resolvedConfig);

      const context = new AuthServerContext(discoveryConfig);
      const [result1, result2] = await Promise.all([context.getMetadata(), context.getMetadata()]);

      expect(fetchServerConfig).toHaveBeenCalledTimes(1);
      expect(result1).toBe(mockMetadata);
      expect(result2).toBe(mockMetadata);
    });

    it('should reset the cache after a failure so the next call retries', async () => {
      const fetchError = new Error('Network error');
      vi.mocked(fetchServerConfig).mockRejectedValueOnce(fetchError);

      const context = new AuthServerContext(discoveryConfig);

      await expect(context.getMetadata()).rejects.toThrow(fetchError);

      vi.mocked(fetchServerConfig).mockResolvedValue(resolvedConfig);
      await expect(context.getMetadata()).resolves.toBe(mockMetadata);
      expect(fetchServerConfig).toHaveBeenCalledTimes(2);
    });

    it('should propagate validation errors', async () => {
      const validationError = new MCPAuthAuthServerError('invalid_server_config');
      vi.mocked(fetchServerConfig).mockResolvedValue(resolvedConfig);
      vi.mocked(validateResolvedMetadata).mockImplementation(() => {
        throw validationError;
      });

      const context = new AuthServerContext(discoveryConfig);

      await expect(context.getMetadata()).rejects.toThrow(validationError);
    });
  });

  describe('getJwks', () => {
    it('should throw if the metadata has no JWKS URI', async () => {
      const { jwks_uri: _removed, ...rest } = mockMetadata;
      const context = new AuthServerContext({ type: 'oidc', metadata: rest });

      await expect(context.getJwks()).rejects.toThrowError(
        matchError('MCPAuthAuthServerError', 'missing_jwks_uri')
      );
    });

    it('should create the remote JWK Set once and reuse the instance', async () => {
      const context = new AuthServerContext(resolvedConfig);

      const jwks1 = await context.getJwks();
      const jwks2 = await context.getJwks();

      expect(jwks1).toBeTypeOf('function');
      expect(jwks2).toBe(jwks1);
    });
  });
});
