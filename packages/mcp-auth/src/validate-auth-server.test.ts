import { describe, expect, it, vi } from 'vitest';

import { MCPAuthAuthServerError } from './errors.js';
import { matchError } from './test-utils.js';
import { type AuthServerMetadata } from './types.js';
import {
  parseAuthServerMetadata,
  validateAuthServerMetadata,
  validateResolvedMetadata,
} from './validate-auth-server.js';

const validMetadata: AuthServerMetadata = Object.freeze({
  issuer: 'https://auth.example.com',
  authorization_endpoint: 'https://auth.example.com/authorize',
  token_endpoint: 'https://auth.example.com/token',
  jwks_uri: 'https://auth.example.com/jwks',
  response_types_supported: ['code'],
  grant_types_supported: ['authorization_code'],
  code_challenge_methods_supported: ['S256'],
  registration_endpoint: 'https://auth.example.com/register',
});

describe('parseAuthServerMetadata', () => {
  it.each([null, undefined, 'string', 42, ['array']])(
    'should throw if the metadata is not an object (%s)',
    (data) => {
      expect(() => parseAuthServerMetadata(data)).toThrowError(
        matchError('MCPAuthAuthServerError', 'invalid_server_metadata')
      );
    }
  );

  it.each(['issuer', 'authorization_endpoint', 'token_endpoint', 'response_types_supported'])(
    'should throw if the required field `%s` is missing',
    (field) => {
      const { [field]: _removed, ...rest }: Record<string, unknown> = { ...validMetadata };
      expect(() => parseAuthServerMetadata(rest)).toThrowError(
        matchError('MCPAuthAuthServerError', 'invalid_server_metadata')
      );
    }
  );

  it('should throw if an optional field has an unexpected type', () => {
    expect(() => parseAuthServerMetadata({ ...validMetadata, jwks_uri: 42 })).toThrowError(
      MCPAuthAuthServerError
    );
    expect(() =>
      parseAuthServerMetadata({ ...validMetadata, scopes_supported: 'not-an-array' })
    ).toThrowError(MCPAuthAuthServerError);
  });

  it('should include the invalid field names in the error cause', () => {
    try {
      parseAuthServerMetadata({ issuer: 'https://auth.example.com' });
    } catch (error) {
      expect(error).toBeInstanceOf(MCPAuthAuthServerError);
      expect(error).toHaveProperty(
        'cause.message',
        'The server metadata has missing or malformed fields: authorization_endpoint, token_endpoint, response_types_supported.'
      );
    }
    expect.assertions(2);
  });

  it('should return the metadata verbatim, keeping unknown fields', () => {
    const metadata = { ...validMetadata, custom_field: 'custom' };
    expect(parseAuthServerMetadata(metadata)).toBe(metadata);
  });
});

describe('validateAuthServerMetadata', () => {
  it('should return no errors or warnings for a fully valid metadata', () => {
    expect(validateAuthServerMetadata(validMetadata)).toEqual({ errors: [], warnings: [] });
  });

  it('should report an error if the `code` response type is not supported', () => {
    const { errors } = validateAuthServerMetadata({
      ...validMetadata,
      response_types_supported: ['token'],
    });
    expect(errors).toEqual([expect.stringContaining('`code` response type')]);
  });

  it('should accept the `code` response type in a combined value', () => {
    const { errors } = validateAuthServerMetadata({
      ...validMetadata,
      response_types_supported: ['code id_token'],
    });
    expect(errors).toEqual([]);
  });

  it('should report an error if the `authorization_code` grant type is not supported', () => {
    const { errors } = validateAuthServerMetadata({
      ...validMetadata,
      grant_types_supported: ['implicit'],
    });
    expect(errors).toEqual([expect.stringContaining('`authorization_code` grant type')]);
  });

  it('should fall back to the RFC 8414 default grant types when omitted', () => {
    const { grant_types_supported: _removed, ...rest } = validMetadata;
    expect(validateAuthServerMetadata(rest).errors).toEqual([]);
  });

  it('should report an error if PKCE is not supported', () => {
    const { code_challenge_methods_supported: _removed, ...rest } = validMetadata;
    expect(validateAuthServerMetadata(rest).errors).toEqual([
      expect.stringContaining('Proof Key for Code Exchange'),
    ]);
  });

  it('should report an error if the `S256` code challenge method is not supported', () => {
    const { errors } = validateAuthServerMetadata({
      ...validMetadata,
      code_challenge_methods_supported: ['plain'],
    });
    expect(errors).toEqual([expect.stringContaining('`S256`')]);
  });

  it('should report a warning if dynamic client registration is not supported', () => {
    const { registration_endpoint: _removed, ...rest } = validMetadata;
    expect(validateAuthServerMetadata(rest).warnings).toEqual([
      expect.stringContaining('Dynamic Client Registration'),
    ]);
  });
});

describe('validateResolvedMetadata', () => {
  it('should not throw for a valid metadata', () => {
    expect(() => {
      validateResolvedMetadata(validMetadata);
    }).not.toThrow();
  });

  it('should throw a `MCPAuthAuthServerError` if the metadata has errors', () => {
    expect(() => {
      validateResolvedMetadata({ ...validMetadata, response_types_supported: ['token'] });
    }).toThrowError(matchError('MCPAuthAuthServerError', 'invalid_server_config'));
  });

  it('should log warnings without throwing', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {
      /* Noop */
    });
    const { registration_endpoint: _removed, ...rest } = validMetadata;

    expect(() => {
      validateResolvedMetadata(rest);
    }).not.toThrow();
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('Dynamic Client Registration'));

    warn.mockRestore();
  });
});
