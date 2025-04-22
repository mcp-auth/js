import assert from 'node:assert';

import { describe, expect, it } from 'vitest';

import { type AuthServerConfig } from '../types/auth-server.js';

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
    expect(result).not.toHaveProperty('errors');
    expect(result.warnings).toEqual([]);
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
        'code_response_type_not_supported',
        'authorization_code_grant_not_supported',
        'pkce_not_supported',
      ])
    );
    expect(result.warnings).toEqual(expect.arrayContaining(['dynamic_registration_not_supported']));
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
    expect(result.warnings).toEqual(['dynamic_registration_not_supported']);
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
      expect.arrayContaining(['s256_code_challenge_method_not_supported'])
    );
  });
});
