import { noop } from '@silverhand/essentials';
import { Router } from 'express';
import httpMocks from 'node-mocks-http';
import snakecaseKeys from 'snakecase-keys';
import { describe, it, expect } from 'vitest';

import { serverMetadataPaths } from '../utils/fetch-server-config.js';

import { createDelegatedRouter } from './create-delegated-router.js';

describe('createDelegatedRouter()', () => {
  const metadata = {
    issuer: 'https://example.com',
    authorizationEndpoint: 'https://example.com/authorize',
    tokenEndpoint: 'https://example.com/token',
    responseTypesSupported: ['code', 'token'],
  };

  it('should return a router instance', () => {
    const router = createDelegatedRouter(metadata);
    expect(router).toBeInstanceOf(Router);
  });

  it('should respond with snake_case metadata on GET /.well-known/oauth-authorization-server', async () => {
    const router = createDelegatedRouter(metadata);
    const request = httpMocks.createRequest({
      method: 'GET',
      url: serverMetadataPaths.oauth,
    });
    const response = httpMocks.createResponse();
    await router(request, response, noop);
    expect(response.statusCode).toBe(200);
    expect(response._getJSONData()).toEqual(snakecaseKeys(metadata));
    expect(response.getHeaders()['content-type']).toBe('application/json');
    expect(response.getHeaders()['access-control-allow-origin']).toBe('*');
  });
});
