import { afterEach, describe, expect, test, vi } from 'vitest';

import { MCPAuthAuthServerError } from '../errors.js';
import { type AuthServerConfig } from '../types/auth-server.js';

import { validateAuthServer } from './validate-auth-server.js';
import { validateServerConfig } from './validate-server-config.js';

vi.mock('./validate-server-config.js');

describe('validateAuthServer', () => {
  const mockAuthServer: AuthServerConfig = {
    // @ts-expect-error
    metadata: {
      issuer: 'https://example.com',
    },
    type: 'oauth',
  };

  afterEach(() => {
    vi.restoreAllMocks();
  });

  test('should call `validateServerConfig` with the server config', () => {
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
    vi.mocked(validateServerConfig).mockReturnValue({
      isValid: true,
      warnings: [],
      successes: [],
    });
    validateAuthServer(validServerConfig);
    expect(validateServerConfig).toHaveBeenCalledWith(validServerConfig);
  });

  test('should throw MCPAuthAuthServerError if server config is invalid', () => {
    const errorDetails = {
      isValid: false,
      errors: [{ description: 'Invalid issuer' }],
      warnings: [],
    };
    // @ts-expect-error
    vi.mocked(validateServerConfig).mockReturnValue(errorDetails);

    expect(() => {
      validateAuthServer(mockAuthServer);
    }).toThrow(new MCPAuthAuthServerError('invalid_server_config', errorDetails));
  });

  test('should log warnings if server config has warnings', () => {
    const warnSpy = vi.spyOn(console, 'warn');
    const warningDetails = {
      isValid: true,
      errors: [],
      warnings: [{ description: 'Some warning' }],
    };
    // @ts-expect-error
    vi.mocked(validateServerConfig).mockReturnValue(warningDetails);

    validateAuthServer(mockAuthServer);

    expect(warnSpy).toHaveBeenCalledOnce();
    expect(warnSpy).toHaveBeenCalledWith(
      // @ts-expect-error
      `The authorization server (issuer: \`${mockAuthServer.metadata.issuer}\`) configuration has warnings:\n\n  - ${warningDetails.warnings[0].description}\n`
    );
  });

  test('should not throw or warn for a valid configuration', () => {
    const warnSpy = vi.spyOn(console, 'warn');
    const validDetails = {
      isValid: true,
      errors: [],
      warnings: [],
    };
    // @ts-expect-error
    vi.mocked(validateServerConfig).mockReturnValue(validDetails);

    expect(() => {
      validateAuthServer(mockAuthServer);
    }).not.toThrow();
    expect(warnSpy).not.toHaveBeenCalled();
  });
});
