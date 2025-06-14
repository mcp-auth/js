import { noop } from '@silverhand/essentials';
import { Router } from 'express';
import httpMocks from 'node-mocks-http';
import snakecaseKeys from 'snakecase-keys';
import { describe, it, expect } from 'vitest';

import { type CamelCaseProtectedResourceMetadata } from '../types/oauth.js';
import { createResourceMetadataEndpoint } from '../utils/create-resource-metadata-endpoint.js';

import { createResourceMetadataRouter } from './create-resource-metadata-router.js';

describe('createResourceMetadataRouter()', () => {
  const metadata1: CamelCaseProtectedResourceMetadata = {
    resource: 'https://api.example.com/v1',
    authorizationServers: ['https://auth.example.com'],
    scopesSupported: ['read', 'write'],
    bearerMethodsSupported: ['header', 'body'],
  };

  const metadata2: CamelCaseProtectedResourceMetadata = {
    resource: 'https://api.example.com/v2',
    authorizationServers: ['https://another-auth.example.com'],
    scopesSupported: ['admin'],
  };

  it('should return a router instance', () => {
    const router = createResourceMetadataRouter([]);
    expect(router).toBeInstanceOf(Router);
  });

  it('should respond with snake_case metadata for a single resource', async () => {
    const router = createResourceMetadataRouter([metadata1]);
    const endpoint = createResourceMetadataEndpoint(metadata1.resource);
    const request = httpMocks.createRequest({
      method: 'GET',
      url: endpoint.pathname,
    });
    const response = httpMocks.createResponse();

    await router(request, response, noop);

    expect(response.statusCode).toBe(200);
    expect(response._getJSONData()).toEqual(snakecaseKeys(metadata1));
    expect(response.getHeaders()['content-type']).toBe('application/json');
    expect(response.getHeaders()['access-control-allow-origin']).toBe('*');
  });

  it('should handle multiple resource metadata entries', async () => {
    const router = createResourceMetadataRouter([metadata1, metadata2]);

    // Test first resource
    const endpoint1 = createResourceMetadataEndpoint(metadata1.resource);
    const request1 = httpMocks.createRequest({
      method: 'GET',
      url: endpoint1.pathname,
    });
    const response1 = httpMocks.createResponse();
    await router(request1, response1, noop);

    expect(response1.statusCode).toBe(200);
    expect(response1._getJSONData()).toEqual(snakecaseKeys(metadata1));

    // Test second resource
    const endpoint2 = createResourceMetadataEndpoint(metadata2.resource);
    const request2 = httpMocks.createRequest({
      method: 'GET',
      url: endpoint2.pathname,
    });
    const response2 = httpMocks.createResponse();
    await router(request2, response2, noop);

    expect(response2.statusCode).toBe(200);
    expect(response2._getJSONData()).toEqual(snakecaseKeys(metadata2));
  });
});
