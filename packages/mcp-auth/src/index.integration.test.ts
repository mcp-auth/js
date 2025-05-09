import express from 'express';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import nock from 'nock';
import snakecaseKeys from 'snakecase-keys';
import request from 'supertest';
import { afterEach, describe, expect, it } from 'vitest';

import { MCPAuth, serverMetadataPaths, type MCPAuthConfig } from './index.js';

afterEach(() => {
  nock.cleanAll();
});

describe('MCPAuth class (routers)', () => {
  const issuer = 'https://example.com';
  const authorizationPath = '/oauth/authorize';
  const tokenPath = '/oauth/token';
  const registrationPath = '/oauth/register';
  const revocationPath = '/oauth/revoke';
  const serverMetadata = Object.freeze({
    issuer,
    authorizationEndpoint: `${issuer}${authorizationPath}`,
    tokenEndpoint: `${issuer}${tokenPath}`,
    responseTypesSupported: ['code'],
    grantTypesSupported: ['authorization_code'],
    codeChallengeMethodsSupported: ['S256'],
    registrationEndpoint: `${issuer}${registrationPath}`,
    revocationEndpoint: `${issuer}${revocationPath}`,
  } satisfies MCPAuthConfig['server']['metadata']);

  it('should create a delegated router with correct metadata', async () => {
    const auth = new MCPAuth({ server: { type: 'oauth', metadata: serverMetadata } });
    const router = auth.delegatedRouter();

    // The metadata should be static and not depend on the remote server
    const metadata = nock(issuer)
      .get(serverMetadataPaths.oauth)
      .reply(500, 'Internal Server Error');

    const app = express();
    app.use(router);
    await request(app).get(serverMetadataPaths.oauth).expect(200, snakecaseKeys(serverMetadata));
    expect(metadata.isDone()).toBe(false);
  });
});

describe('MCPAuth class (bearerAuth)', () => {
  const audience = 'https://api.example.com';
  const metadata = Object.freeze({
    issuer: 'https://example.com',
    authorizationEndpoint: 'https://example.com/oauth/authorize',
    tokenEndpoint: 'https://example.com/oauth/token',
    jwksUri: 'https://example.com/oauth/jwks',
    responseTypesSupported: ['code'],
    grantTypesSupported: ['authorization_code'],
    codeChallengeMethodsSupported: ['S256'],
  } satisfies MCPAuthConfig['server']['metadata']);
  const createApp = () => {
    const auth = new MCPAuth({ server: { type: 'oauth', metadata } });
    const app = express();
    app.get(
      '/',
      auth.bearerAuth('jwt', { audience, requiredScopes: ['read', 'write'] }),
      (_, response) => {
        response.status(200).send('Success');
      }
    );
    return app;
  };

  it('should return 401 if no Authorization header is provided', async () => {
    await request(createApp()).get('/').expect(401);
  });

  it('should return 401 if the token is invalid', async () => {
    await request(createApp()).get('/').set('Authorization', 'Bearer invalid-token').expect(401);
  });

  it('should return 403 if the token does not have required scopes', async () => {
    const alg = 'ES256';
    const { privateKey, publicKey } = await generateKeyPair(alg);
    const jwks = nock(metadata.issuer)
      .get('/oauth/jwks')
      .reply(200, {
        keys: [await exportJWK(publicKey)],
      });
    const validToken = await new SignJWT({
      iss: metadata.issuer,
      aud: audience,
      client_id: 'client12345',
      sub: 'user12345',
    })
      .setProtectedHeader({ alg })
      .setIssuedAt()
      .setExpirationTime('1h')
      .sign(privateKey);
    await request(createApp()).get('/').set('Authorization', `Bearer ${validToken}`).expect(403);
    expect(jwks.isDone()).toBe(true);
  });

  it('should return 200 if the token is valid and has required scopes', async () => {
    const alg = 'ES256';
    const { privateKey, publicKey } = await generateKeyPair(alg);
    const jwks = nock(metadata.issuer)
      .get('/oauth/jwks')
      .reply(200, {
        keys: [await exportJWK(publicKey)],
      });
    const validToken = await new SignJWT({
      iss: metadata.issuer,
      aud: audience,
      client_id: 'client12345',
      sub: 'user12345',
      scopes: ['read', 'write'],
    })
      .setProtectedHeader({ alg })
      .setIssuedAt()
      .setExpirationTime('1h')
      .sign(privateKey);
    await request(createApp()).get('/').set('Authorization', `Bearer ${validToken}`).expect(200);
    expect(jwks.isDone()).toBe(true);
  });
});
