import { describe, expect, it } from 'vitest';

import { BearerWWWAuthenticateHeader } from './bearer-www-authenticate-header.js';

describe('BearerWWWAuthenticateHeader', () => {
  it('should have the correct header name', () => {
    const header = new BearerWWWAuthenticateHeader();
    expect(header.headerName).toBe('WWW-Authenticate');
  });

  it('should generate an empty string if no parameters are set', () => {
    const header = new BearerWWWAuthenticateHeader();
    expect(header.toString()).toBe('');
  });

  it('should build the header string correctly from chained calls', () => {
    const header = new BearerWWWAuthenticateHeader();
    header
      .setParameterIfValueExists('realm', 'example')
      .setParameterIfValueExists('error', 'invalid_token')
      .setParameterIfValueExists('error_description', 'The access token expired')
      .setParameterIfValueExists(
        'resource_metadata',
        'https://example.com/.well-known/oauth-protected-resource'
      );

    expect(header.toString()).toBe(
      'Bearer realm="example", error="invalid_token", error_description="The access token expired", resource_metadata="https://example.com/.well-known/oauth-protected-resource"'
    );
  });

  it('should ignore parameters that are empty, null, or undefined', () => {
    const header = new BearerWWWAuthenticateHeader();

    header
      .setParameterIfValueExists('realm', 'example')
      .setParameterIfValueExists('scope', '') // Empty string
      .setParameterIfValueExists('error', 'invalid_token')
      .setParameterIfValueExists('error_uri', undefined) // Undefined value
      .setParameterIfValueExists('error_description', ''); // Empty string

    expect(header.toString()).toBe('Bearer realm="example", error="invalid_token"');
  });
});
