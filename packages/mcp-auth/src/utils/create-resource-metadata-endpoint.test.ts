import { describe, expect, it } from 'vitest';

import { createResourceMetadataEndpoint } from './create-resource-metadata-endpoint.js';

describe('createResourceMetadataEndpoint', () => {
  it('should throw an error if the resource is not a valid URL', () => {
    expect(() => createResourceMetadataEndpoint('not a url')).toThrow(
      'Invalid resource: not a url'
    );
  });

  it('should return the metadata endpoint for a resource with root path', () => {
    const resource = 'https://example.com/';
    const metadataEndpoint = createResourceMetadataEndpoint(resource);
    expect(metadataEndpoint.toString()).toBe(
      'https://example.com/.well-known/oauth-protected-resource'
    );
  });

  it('should return the metadata endpoint for a resource with a sub-path', () => {
    const resource = 'https://example.com/api/v1';
    const metadataEndpoint = createResourceMetadataEndpoint(resource);
    expect(metadataEndpoint.toString()).toBe(
      'https://example.com/.well-known/oauth-protected-resource/api/v1'
    );
  });

  it('should return the metadata endpoint for a resource with a sub-path and trailing slash', () => {
    const resource = 'https://example.com/api/v1/';
    const metadataEndpoint = createResourceMetadataEndpoint(resource);
    expect(metadataEndpoint.toString()).toBe(
      'https://example.com/.well-known/oauth-protected-resource/api/v1/'
    );
  });

  it('should preserve the origin of the resource', () => {
    const resource = 'http://localhost:3000/foo';
    const metadataEndpoint = createResourceMetadataEndpoint(resource);
    expect(metadataEndpoint.toString()).toBe(
      'http://localhost:3000/.well-known/oauth-protected-resource/foo'
    );
  });

  it('should ignore query parameters and hash from the resource', () => {
    const resource = 'https://example.com/api/v1?foo=bar#baz';
    const metadataEndpoint = createResourceMetadataEndpoint(resource);
    expect(metadataEndpoint.toString()).toBe(
      'https://example.com/.well-known/oauth-protected-resource/api/v1'
    );
  });
});
