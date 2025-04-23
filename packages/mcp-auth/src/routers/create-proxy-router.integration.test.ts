import express from 'express';
import nock from 'nock';
import request from 'supertest';
import { afterEach, describe, expect, it } from 'vitest';

import { defaultPaths } from '../consts/mcp.js';

import { createProxyRouter } from './create-proxy-router.js';

describe('createProxyRouter() proxy routes', () => {
  const issuer = 'https://bar.com';
  const authorizationPath = '/authorize-path';
  const tokenPath = '/token-path';
  const registrationPath = '/registration-path';
  const revocationPath = '/revocation-path';

  afterEach(() => {
    nock.cleanAll();
  });

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
});
