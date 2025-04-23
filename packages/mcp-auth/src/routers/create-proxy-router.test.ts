import { noop } from '@silverhand/essentials';
import httpMocks from 'node-mocks-http';
import snakecaseKeys from 'snakecase-keys';
import { describe, expect, it } from 'vitest';

import { serverMetadataPaths } from '../utils/fetch-server-config.js';

import { createProxyRouter } from './create-proxy-router.js';

describe('createProxyRouter() metadata route', () => {
  it('should allow minimal configuration', async () => {
    const router = createProxyRouter({
      baseUrl: 'https://foo.com',
      metadata: {
        issuer: 'https://bar.com',
        authorizationEndpoint: 'https://bar.com/authorize',
        tokenEndpoint: 'https://bar.com/token',
        responseTypesSupported: ['code', 'token'],
      },
    });
    const request = httpMocks.createRequest({
      method: 'GET',
      url: serverMetadataPaths.oauth,
    });
    const response = httpMocks.createResponse();
    await router(request, response, noop);
    expect(response.statusCode).toBe(200);
    expect(response._getJSONData()).toEqual(
      snakecaseKeys({
        issuer: 'https://bar.com',
        authorizationEndpoint: 'https://foo.com/authorize',
        tokenEndpoint: 'https://foo.com/token',
        responseTypesSupported: ['code', 'token'],
      })
    );
    expect(response.getHeaders()['content-type']).toBe('application/json');
    expect(response.getHeaders()['access-control-allow-origin']).toBe('*');
  });

  it('should rewrite certain endpoints based on the provided base URL', async () => {
    const router = createProxyRouter({
      baseUrl: 'https://foo.com',
      metadata: {
        issuer: 'https://bar.com',
        authorizationEndpoint: 'https://bar.com/authorize-path',
        tokenEndpoint: 'https://bar.com/token-path',
        responseTypesSupported: ['code', 'token'],
        registrationEndpoint: 'https://bar.com/register-path',
        revocationEndpoint: 'https://bar.com/revoke-path',
        opPolicyUri: 'https://bar.com/policy',
        opTosUri: 'https://bar.com/tos',
      },
    });
    const request = httpMocks.createRequest({
      method: 'GET',
      url: serverMetadataPaths.oauth,
    });
    const response = httpMocks.createResponse();
    await router(request, response, noop);
    expect(response.statusCode).toBe(200);
    expect(response._getJSONData()).toEqual(
      snakecaseKeys({
        issuer: 'https://bar.com',
        authorizationEndpoint: 'https://foo.com/authorize',
        tokenEndpoint: 'https://foo.com/token',
        registrationEndpoint: 'https://foo.com/register',
        revocationEndpoint: 'https://foo.com/revoke',
        responseTypesSupported: ['code', 'token'],
        opPolicyUri: 'https://bar.com/policy',
        opTosUri: 'https://bar.com/tos',
      })
    );
    expect(response.getHeaders()['content-type']).toBe('application/json');
    expect(response.getHeaders()['access-control-allow-origin']).toBe('*');
  });

  it('should handle custom endpoint overrides', async () => {
    const router = createProxyRouter({
      baseUrl: 'https://foo.com',
      metadata: {
        issuer: 'https://bar.com',
        authorizationEndpoint: 'https://bar.com/authorize-path',
        tokenEndpoint: 'https://bar.com/token-path',
        responseTypesSupported: ['code', 'token'],
        registrationEndpoint: 'https://bar.com/register-path',
        revocationEndpoint: 'https://bar.com/revoke-path',
      },
      overrides: {
        authorizationPath: '/custom-auth',
        tokenPath: '/custom-token',
        registrationPath: '/custom-register',
        revocationPath: '/custom-revoke',
      },
    });
    const request = httpMocks.createRequest({
      method: 'GET',
      url: serverMetadataPaths.oauth,
    });
    const response = httpMocks.createResponse();
    await router(request, response, noop);
    expect(response.statusCode).toBe(200);
    expect(response._getJSONData()).toEqual(
      snakecaseKeys({
        issuer: 'https://bar.com',
        authorizationEndpoint: 'https://foo.com/custom-auth',
        tokenEndpoint: 'https://foo.com/custom-token',
        responseTypesSupported: ['code', 'token'],
        registrationEndpoint: 'https://foo.com/custom-register',
        revocationEndpoint: 'https://foo.com/custom-revoke',
      })
    );
  });
});
