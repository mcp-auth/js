import express from 'express';
import { type Request as ExpressRequest, type Response as ExpressResponse } from 'express';
import { type Options } from 'http-proxy-middleware';
import nock from 'nock';
import request from 'supertest';
import { afterEach, describe, expect, it } from 'vitest';

import { defaultPaths } from '../consts/mcp.js';

import { createProxyRouter } from './create-proxy-router.js';

const issuer = 'https://bar.com';
const authorizationPath = '/authorize-path';
const tokenPath = '/token-path';
const registrationPath = '/registration-path';
const revocationPath = '/revocation-path';

afterEach(() => {
  nock.cleanAll();
});

describe('createProxyRouter() proxy routes', () => {
  it('should proxy requests to the enpoints defined in the metadata', async () => {
    const authorization = nock(issuer).get(authorizationPath).query(true).reply(303, '', {
      Location: 'https://bar.com/redirect',
    });
    const tokenData = { access_token: 'access-token', token_type: 'Bearer', expires_in: 3600 };
    const token = nock(issuer).post(tokenPath).reply(200, tokenData);
    const registrationData = { client_id: 'client-id', client_secret: 'client-secret' };
    const registration = nock(issuer).post(registrationPath).reply(201, registrationData);
    const revocation = nock(issuer).post(revocationPath).reply(200, {});
    const app = express();
    const router = createProxyRouter({
      baseUrl: 'https://foo.com',
      metadata: {
        issuer,
        authorizationEndpoint: `${issuer}${authorizationPath}`,
        tokenEndpoint: `${issuer}${tokenPath}`,
        registrationEndpoint: `${issuer}${registrationPath}`,
        revocationEndpoint: `${issuer}${revocationPath}`,
        responseTypesSupported: ['code', 'token'],
      },
    });
    app.use(router);

    const authorizationResponse = await request(app)
      .get(defaultPaths.authorizationPath)
      .query({ response_type: 'code', client_id: 'client-id' });
    expect(authorizationResponse.status).toBe(303);
    expect(authorizationResponse.headers.location).toBe('https://bar.com/redirect');
    expect(authorization.isDone()).toBe(true);

    const tokenResponse = await request(app).post(defaultPaths.tokenPath).send({
      grant_type: 'client_credentials',
      client_id: 'client-id',
      client_secret: 'client-secret',
    });
    expect(tokenResponse.status).toBe(200);
    expect(tokenResponse.body).toEqual(tokenData);
    expect(token.isDone()).toBe(true);

    const registrationResponse = await request(app)
      .post(defaultPaths.registrationPath)
      .send({ client_name: 'Test Client' });
    expect(registrationResponse.status).toBe(201);
    expect(registrationResponse.body).toEqual(registrationData);
    expect(registration.isDone()).toBe(true);

    const revocationResponse = await request(app)
      .post(defaultPaths.revocationPath)
      .send({ token: 'access-token', token_type_hint: 'access_token' });
    expect(revocationResponse.status).toBe(200);
    expect(revocationResponse.body).toEqual({});
    expect(revocation.isDone()).toBe(true);
  });

  it('should respond with 404 for unsupported paths', async () => {
    const remoteServer = nock(issuer)
      .get(() => true)
      .reply(200, 'Remote server response');
    const app = express();
    const router = createProxyRouter({
      baseUrl: 'https://foo.com',
      metadata: {
        issuer,
        authorizationEndpoint: `${issuer}${authorizationPath}`,
        tokenEndpoint: `${issuer}${tokenPath}`,
        responseTypesSupported: ['code', 'token'],
      },
    });
    app.use(router);

    // Test the remote authorization endpoint instead of MCP server's path
    const response = await request(app)
      .get(authorizationPath)
      .query({ response_type: 'code', client_id: 'client-id' });
    expect(response.status).toBe(404);
    expect(remoteServer.isDone()).toBe(false);
  });

  it('should proxy requests with query parameters', async () => {
    const queryParams = { response_type: 'code', client_id: 'client-id' };
    const authorization = nock(issuer)
      .get(authorizationPath)
      .query(queryParams)
      .reply(303, '', { Location: 'https://bar.com/redirect' });
    const app = express();
    const router = createProxyRouter({
      baseUrl: 'https://foo.com',
      metadata: {
        issuer,
        authorizationEndpoint: `${issuer}${authorizationPath}`,
        tokenEndpoint: `${issuer}${tokenPath}`,
        responseTypesSupported: ['code', 'token'],
      },
    });
    app.use(router);
    const response = await request(app).get(defaultPaths.authorizationPath).query(queryParams);
    expect(response.status).toBe(303);
    expect(response.headers.location).toBe('https://bar.com/redirect');
    expect(authorization.isDone()).toBe(true);
  });

  it('should not proxy requests when certain endpoints are not defined in metadata', async () => {
    const authorization = nock(issuer).get(registrationPath).reply(501, 'Not Implemented');
    const app = express();
    const router = createProxyRouter({
      baseUrl: 'https://foo.com',
      metadata: {
        issuer,
        authorizationEndpoint: `${issuer}${authorizationPath}`,
        tokenEndpoint: `${issuer}${tokenPath}`,
        responseTypesSupported: ['code', 'token'],
      },
    });
    app.use(router);
    const response = await request(app).get(defaultPaths.registrationPath);
    expect(response.status).toBe(404);
    expect(authorization.isDone()).toBe(false);
  });
});

describe('createProxyRouter() proxy options', () => {
  it('should apply custom proxy options', async () => {
    const newIssuer = 'https://baz.com';
    const authorization = nock(newIssuer)
      .get(authorizationPath)
      .matchHeader('X-Custom-Header', 'CustomValue')
      .query(true)
      .reply(303, '', { Location: 'https://bar.com/redirect' });
    const proxyOptions: Partial<Options<ExpressRequest, ExpressResponse>> = {
      on: {
        proxyReq: (proxyRequest) => {
          // Add custom headers or modify the request here
          proxyRequest.setHeader('X-Custom-Header', 'CustomValue');
        },
        proxyRes: (_, __, response) => {
          // Modify the response if needed
          response.setHeader('X-Proxy-Response', 'Modified');
        },
      },
      target: newIssuer,
    };
    const app = express();
    const router = createProxyRouter({
      baseUrl: 'https://foo.com',
      metadata: {
        issuer,
        authorizationEndpoint: `${issuer}${authorizationPath}`,
        tokenEndpoint: `${issuer}${tokenPath}`,
        responseTypesSupported: ['code', 'token'],
      },
      proxyOptions,
    });
    app.use(router);

    const response = await request(app)
      .get(defaultPaths.authorizationPath)
      .query({ response_type: 'code', client_id: 'client-id' });

    expect(response.status).toBe(303);
    expect(response.headers.location).toBe('https://bar.com/redirect');
    expect(response.headers['x-proxy-response']).toBe('Modified');
    expect(authorization.isDone()).toBe(true);
  });
});
