import { vi, describe, beforeEach, expect, it } from 'vitest';
import createFetchMock from 'vitest-fetch-mock';

import { fetchServerConfig, fetchServerConfigByWellKnownUrl } from './fetch-server-config.js';

const fetchMock = createFetchMock(vi);

fetchMock.enableMocks();

beforeEach(() => {
  fetchMock.resetMocks();
});

describe('fetchServerConfigByWellKnownUrl', () => {
  const sampleIssuer = 'https://example.com';
  const sampleWellKnownUrl = 'https://example.com/.well-known/oauth-authorization-server';
  const sampleResponse = Object.freeze({
    issuer: sampleIssuer,
    authorization_endpoint: 'https://example.com/oauth/authorize',
    token_endpoint: 'https://example.com/oauth/token',
  });
  const sampleErrorResponse = {
    error: 'invalid_request',
    error_description: 'Invalid request parameters',
  };

  it('should throw an error if the fetch fails', async () => {
    fetchMock.mockResponseOnceIf(sampleWellKnownUrl, JSON.stringify(sampleErrorResponse), {
      status: 500,
    });

    await expect(
      fetchServerConfigByWellKnownUrl(sampleWellKnownUrl, { type: 'oauth' })
    ).rejects.toThrowErrorMatchingInlineSnapshot(
      '[MCPAuthConfigError: Failed to fetch server config from https://example.com/.well-known/oauth-authorization-server: ]'
    );

    expect(fetchMock).toHaveBeenCalledWith(sampleWellKnownUrl);
  });

  it('should throw an error if the metadata is not an object', async () => {
    fetchMock.mockResponseOnceIf(sampleWellKnownUrl, 'null', { status: 200 });

    await expect(
      fetchServerConfigByWellKnownUrl(sampleWellKnownUrl, { type: 'oauth' })
    ).rejects.toThrowErrorMatchingInlineSnapshot(
      '[MCPAuthAuthServerError: The server metadata is invalid or malformed.]'
    );

    expect(fetchMock).toHaveBeenCalledWith(sampleWellKnownUrl);
  });

  it('throw an error if the metadata is malformed', async () => {
    fetchMock.mockResponseOnceIf(sampleWellKnownUrl, JSON.stringify(sampleResponse), {
      status: 200,
    });

    await expect(
      fetchServerConfigByWellKnownUrl(sampleWellKnownUrl, {
        type: 'oauth',
      })
    ).rejects.toThrowErrorMatchingInlineSnapshot(
      '[MCPAuthAuthServerError: The server metadata is invalid or malformed.]'
    );

    expect(fetchMock).toHaveBeenCalledWith(sampleWellKnownUrl);
  });

  it('should fetch server config successfully with data transpilation', async () => {
    fetchMock.mockResponseOnceIf(sampleWellKnownUrl, JSON.stringify(sampleResponse), {
      status: 200,
    });

    const config = await fetchServerConfigByWellKnownUrl(sampleWellKnownUrl, {
      type: 'oauth',
      transpileData: (data) => ({ ...data, response_types_supported: ['code'] }),
    });

    expect(config).toEqual({
      type: 'oauth',
      metadata: {
        issuer: sampleIssuer,
        authorizationEndpoint: 'https://example.com/oauth/authorize',
        tokenEndpoint: 'https://example.com/oauth/token',
        responseTypesSupported: ['code'],
      },
    });
  });
});

describe('fetchServerConfig (OAuth)', () => {
  const sampleResponse = Object.freeze({
    authorization_endpoint: 'https://example.com/oauth/authorize',
    token_endpoint: 'https://example.com/oauth/token',
    response_types_supported: ['code'],
  });

  it('should fetch server config using the well-known URL for OAuth', async () => {
    fetchMock.mockResponseOnceIf(
      'https://example.com/.well-known/oauth-authorization-server',
      JSON.stringify({ ...sampleResponse, issuer: 'https://example.com/' }),
      { status: 200 }
    );
    const config = await fetchServerConfig('https://example.com', { type: 'oauth' });
    expect(config).toEqual({
      type: 'oauth',
      metadata: {
        issuer: 'https://example.com/',
        authorizationEndpoint: 'https://example.com/oauth/authorize',
        tokenEndpoint: 'https://example.com/oauth/token',
        responseTypesSupported: ['code'],
      },
    });
  });

  it('should fetch server config with path in issuer for OAuth', async () => {
    fetchMock.mockResponseOnceIf(
      'https://example.com/.well-known/oauth-authorization-server/path',
      JSON.stringify({ ...sampleResponse, issuer: 'https://example.com/path' }),
      { status: 200 }
    );

    const config = await fetchServerConfig('https://example.com/path', { type: 'oauth' });
    expect(config).toEqual({
      type: 'oauth',
      metadata: {
        issuer: 'https://example.com/path',
        authorizationEndpoint: 'https://example.com/oauth/authorize',
        tokenEndpoint: 'https://example.com/oauth/token',
        responseTypesSupported: ['code'],
      },
    });
  });
});

describe('fetchServerConfig (OIDC)', () => {
  it('should fetch server config using the well-known URL for OIDC', async () => {
    fetchMock.mockResponseOnceIf(
      'https://example.com/.well-known/openid-configuration',
      JSON.stringify({
        issuer: 'https://example.com/',
        authorization_endpoint: 'https://example.com/authorize',
        token_endpoint: 'https://example.com/token',
        response_types_supported: ['code'],
      }),
      { status: 200 }
    );
    const config = await fetchServerConfig('https://example.com', { type: 'oidc' });
    expect(config).toEqual({
      type: 'oidc',
      metadata: {
        issuer: 'https://example.com/',
        authorizationEndpoint: 'https://example.com/authorize',
        tokenEndpoint: 'https://example.com/token',
        responseTypesSupported: ['code'],
      },
    });
  });

  it('should fetch server config with path in issuer for OIDC', async () => {
    fetchMock.mockResponseOnceIf(
      'https://example.com/path/.well-known/openid-configuration',
      JSON.stringify({
        issuer: 'https://example.com/path',
        authorization_endpoint: 'https://example.com/path/authorize',
        token_endpoint: 'https://example.com/path/token',
        response_types_supported: ['code'],
      }),
      { status: 200 }
    );
    const config = await fetchServerConfig('https://example.com/path', { type: 'oidc' });
    expect(config).toEqual({
      type: 'oidc',
      metadata: {
        issuer: 'https://example.com/path',
        authorizationEndpoint: 'https://example.com/path/authorize',
        tokenEndpoint: 'https://example.com/path/token',
        responseTypesSupported: ['code'],
      },
    });
  });

  it('should throw an error if the OIDC fetch fails', async () => {
    fetchMock.mockResponseOnceIf(
      'https://example.com/.well-known/openid-configuration',
      JSON.stringify({ error: 'invalid_request', error_description: 'Invalid request parameters' }),
      { status: 500 }
    );

    await expect(
      fetchServerConfig('https://example.com', { type: 'oidc' })
    ).rejects.toThrowErrorMatchingInlineSnapshot(
      '[MCPAuthConfigError: Failed to fetch server config from https://example.com/.well-known/openid-configuration: ]'
    );
  });
});
