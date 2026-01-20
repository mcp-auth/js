import assert from 'node:assert';

import { describe, expect, it } from 'vitest';

import { type AuthServerConfig, type ResolvedAuthServerConfig } from '../types/auth-server.js';

import { validateServerConfig } from './validate-server-config.js';

describe('validateServerConfig', () => {
  it('should have set `isValid` to true if the server config is valid', () => {
    const config: AuthServerConfig = {
      type: 'oauth',
      metadata: {
        issuer: 'https://example.com',
        authorizationEndpoint: 'https://example.com/oauth/authorize',
        tokenEndpoint: 'https://example.com/oauth/token',
        responseTypesSupported: ['code'],
        grantTypesSupported: ['authorization_code'],
        codeChallengeMethodsSupported: ['S256'],
        registrationEndpoint: 'https://example.com/register',
      },
    };

    const result = validateServerConfig(config);
    expect(result.isValid).toBe(true);
    expect(result).not.toHaveProperty('successes');
    expect(result).not.toHaveProperty('errors');
    expect(result.warnings).toEqual([]);
  });

  it('should have set `isValid` to true if the server config is valid without grant types', () => {
    const config: AuthServerConfig = {
      type: 'oauth',
      metadata: {
        issuer: 'https://example.com',
        authorizationEndpoint: 'https://example.com/oauth/authorize',
        tokenEndpoint: 'https://example.com/oauth/token',
        responseTypesSupported: ['code'],
        codeChallengeMethodsSupported: ['S256'],
      },
    };

    const result = validateServerConfig(config);
    expect(result.isValid).toBe(true);
    expect(result).not.toHaveProperty('successes');
    expect(result).not.toHaveProperty('errors');
  });

  it("should have set `isValid` to false if the server config's grant types are invalid", () => {
    const config: AuthServerConfig = {
      type: 'oauth',
      metadata: {
        issuer: 'https://example.com',
        authorizationEndpoint: 'https://example.com/oauth/authorize',
        tokenEndpoint: 'https://example.com/oauth/token',
        responseTypesSupported: ['code'],
        grantTypesSupported: ['invalid_grant_type'],
        codeChallengeMethodsSupported: ['S256'],
      },
    };

    const result = validateServerConfig(config);
    assert(!result.isValid, 'Expected isValid to be false');
    expect(result.errors).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: 'authorization_code_grant_not_supported' }),
      ])
    );
  });

  it('should have set `isValid` to false if the server config is invalid', () => {
    const config: AuthServerConfig = {
      type: 'oauth',
      metadata: {
        issuer: 'https://example.com',
        authorizationEndpoint: 'https://example.com/oauth/authorize',
        tokenEndpoint: 'https://example.com/oauth/token',
        responseTypesSupported: ['token'], // Invalid response type
      },
    };

    const result = validateServerConfig(config);
    assert(!result.isValid, 'Expected isValid to be false');
    expect(result.errors).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: 'code_response_type_not_supported' }),
        expect.objectContaining({ code: 'pkce_not_supported' }),
      ])
    );
    expect(result.warnings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: 'dynamic_registration_not_supported' }),
      ])
    );
  });

  it('should return warnings if the server config has dynamic registration not supported', () => {
    const config: AuthServerConfig = {
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

    const result = validateServerConfig(config);
    expect(result.isValid).toBe(true);
    expect(result).not.toHaveProperty('errors');
    expect(result.warnings).toEqual([
      expect.objectContaining({ code: 'dynamic_registration_not_supported' }),
    ]);
  });

  it('should check code challenge methods', () => {
    const config: AuthServerConfig = {
      type: 'oauth',
      metadata: {
        issuer: 'https://example.com',
        authorizationEndpoint: 'https://example.com/oauth/authorize',
        tokenEndpoint: 'https://example.com/oauth/token',
        responseTypesSupported: ['code'],
        grantTypesSupported: ['authorization_code'],
        codeChallengeMethodsSupported: ['plain'],
      },
    };

    const result = validateServerConfig(config);
    assert(!result.isValid, 'Expected isValid to be false');
    expect(result.errors).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: 's256_code_challenge_method_not_supported' }),
      ])
    );
  });

  it('should return invalid_server_metadata error when metadata is missing required fields', () => {
    const config = {
      type: 'oauth',
      metadata: {
        // Missing required fields: issuer, authorizationEndpoint, tokenEndpoint, responseTypesSupported
      },
    } as unknown as ResolvedAuthServerConfig;

    const result = validateServerConfig(config);
    assert(!result.isValid, 'Expected isValid to be false');
    expect(result.errors).toEqual(
      expect.arrayContaining([expect.objectContaining({ code: 'invalid_server_metadata' })])
    );
    // Should have the ZodError as the cause
    expect(result.errors[0]?.cause).toBeDefined();
  });
});

describe('validateServerConfig with verbose mode', () => {
  it('should return successes when verbose is true', () => {
    const config: AuthServerConfig = {
      type: 'oauth',
      metadata: {
        issuer: 'https://example.com',
        authorizationEndpoint: 'https://example.com/oauth/authorize',
        tokenEndpoint: 'https://example.com/oauth/token',
        responseTypesSupported: ['code'],
        grantTypesSupported: ['authorization_code'],
        codeChallengeMethodsSupported: ['S256'],
        registrationEndpoint: 'https://example.com/register',
      },
    };

    const result = validateServerConfig(config, true);
    expect(result.isValid).toBe(true);
    expect(result.successes).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: 'server_metadata_valid' }),
        expect.objectContaining({ code: 'code_response_type_supported' }),
        expect.objectContaining({ code: 'authorization_code_grant_supported' }),
        expect.objectContaining({ code: 'pkce_supported' }),
        expect.objectContaining({ code: 's256_code_challenge_method_supported' }),
        expect.objectContaining({ code: 'dynamic_registration_supported' }),
      ])
    );
  });
});
