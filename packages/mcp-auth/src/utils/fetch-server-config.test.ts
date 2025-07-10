import nock from 'nock';
import { describe, expect, it, afterEach } from 'vitest';

import { fetchServerConfig, fetchServerConfigByWellKnownUrl } from './fetch-server-config.js';

afterEach(() => {
  nock.cleanAll();
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
    const wellKnown = nock(sampleIssuer)
      .get('/.well-known/oauth-authorization-server')
      .reply(500, sampleErrorResponse);

    await expect(
      fetchServerConfigByWellKnownUrl(sampleWellKnownUrl, { type: 'oauth' })
    ).rejects.toThrowErrorMatchingInlineSnapshot(
      '[MCPAuthConfigError: Failed to fetch server config from https://example.com/.well-known/oauth-authorization-server: Internal Server Error]'
    );
    expect(wellKnown.isDone()).toBe(true);
  });

  it('should throw an error if the metadata is not an object', async () => {
    const wellKnown = nock(sampleIssuer)
      .get('/.well-known/oauth-authorization-server')
      .reply(200, 'null');

    await expect(
      fetchServerConfigByWellKnownUrl(sampleWellKnownUrl, { type: 'oauth' })
    ).rejects.toThrowErrorMatchingInlineSnapshot(
      '[MCPAuthAuthServerError: The server metadata is invalid or malformed.]'
    );
    expect(wellKnown.isDone()).toBe(true);
  });

  it('throw an error if the metadata is malformed', async () => {
    const wellKnown = nock(sampleIssuer)
      .get('/.well-known/oauth-authorization-server')
      .reply(200, sampleResponse);

    await expect(
      fetchServerConfigByWellKnownUrl(sampleWellKnownUrl, {
        type: 'oauth',
      })
    ).rejects.toThrowErrorMatchingInlineSnapshot(
      '[MCPAuthAuthServerError: The server metadata is invalid or malformed.]'
    );

    expect(wellKnown.isDone()).toBe(true);
  });

  it('should fetch server config successfully with data transpilation', async () => {
    const wellKnown = nock(sampleIssuer)
      .get('/.well-known/oauth-authorization-server')
      .reply(200, sampleResponse);
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
    expect(wellKnown.isDone()).toBe(true);
  });
});

describe('fetchServerConfig (OAuth)', () => {
  const sampleResponse = Object.freeze({
    authorization_endpoint: 'https://example.com/oauth/authorize',
    token_endpoint: 'https://example.com/oauth/token',
    response_types_supported: ['code'],
    scopes_supported: ['scope1', 'scope2', 'scope3'],
  });

  it('should fetch server config using the well-known URL for OAuth', async () => {
    const wellKnown = nock('https://example.com')
      .get('/.well-known/oauth-authorization-server')
      .reply(200, { ...sampleResponse, issuer: 'https://example.com/' });
    const config = await fetchServerConfig('https://example.com', { type: 'oauth' });
    expect(config).toEqual({
      type: 'oauth',
      metadata: {
        issuer: 'https://example.com/',
        authorizationEndpoint: 'https://example.com/oauth/authorize',
        tokenEndpoint: 'https://example.com/oauth/token',
        responseTypesSupported: ['code'],
        scopesSupported: ['scope1', 'scope2', 'scope3'],
      },
    });
    expect(wellKnown.isDone()).toBe(true);
  });

  it('should fetch server config with path in issuer for OAuth', async () => {
    const wellKnown = nock('https://example.com')
      .get('/.well-known/oauth-authorization-server/path')
      .reply(200, { ...sampleResponse, issuer: 'https://example.com/path' });
    const config = await fetchServerConfig('https://example.com/path', { type: 'oauth' });
    expect(config).toEqual({
      type: 'oauth',
      metadata: {
        issuer: 'https://example.com/path',
        authorizationEndpoint: 'https://example.com/oauth/authorize',
        tokenEndpoint: 'https://example.com/oauth/token',
        responseTypesSupported: ['code'],
        scopesSupported: ['scope1', 'scope2', 'scope3'],
      },
    });
    expect(wellKnown.isDone()).toBe(true);
  });
});

describe('fetchServerConfig (OIDC)', () => {
  it('should fetch server config using the well-known URL for OIDC', async () => {
    const wellKnown = nock('https://example.com')
      .get('/.well-known/openid-configuration')
      .reply(200, {
        issuer: 'https://example.com/',
        authorization_endpoint: 'https://example.com/authorize',
        token_endpoint: 'https://example.com/token',
        response_types_supported: ['code'],
        scopes_supported: ['openid', 'profile', 'email'],
      });
    const config = await fetchServerConfig('https://example.com', { type: 'oidc' });
    expect(config).toEqual({
      type: 'oidc',
      metadata: {
        issuer: 'https://example.com/',
        authorizationEndpoint: 'https://example.com/authorize',
        tokenEndpoint: 'https://example.com/token',
        responseTypesSupported: ['code'],
        scopesSupported: ['openid', 'profile', 'email'],
      },
    });
    expect(wellKnown.isDone()).toBe(true);
  });

  it('should fetch server config with path in issuer for OIDC', async () => {
    const wellKnown = nock('https://example.com')
      .get('/path/.well-known/openid-configuration')
      .reply(200, {
        issuer: 'https://example.com/path',
        authorization_endpoint: 'https://example.com/path/authorize',
        token_endpoint: 'https://example.com/path/token',
        response_types_supported: ['code'],
      });
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
    expect(wellKnown.isDone()).toBe(true);
  });

  it('should throw an error if the OIDC fetch fails', async () => {
    const wellKnown = nock('https://example.com')
      .get('/.well-known/openid-configuration')
      .reply(500, { error: 'invalid_request', error_description: 'Invalid request parameters' });
    await expect(
      fetchServerConfig('https://example.com', { type: 'oidc' })
    ).rejects.toThrowErrorMatchingInlineSnapshot(
      '[MCPAuthConfigError: Failed to fetch server config from https://example.com/.well-known/openid-configuration: Internal Server Error]'
    );
    expect(wellKnown.isDone()).toBe(true);
  });
});
