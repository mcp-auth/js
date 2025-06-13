import express from 'express';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import nock from 'nock';
import snakecaseKeys from 'snakecase-keys';
import request from 'supertest';
import { afterEach, describe, expect, it } from 'vitest';

import {
  type AuthServerConfig,
  type AuthServerModeConfig,
  MCPAuth,
  serverMetadataPaths,
} from './index.js';
import { type ResourceServerConfig } from './types/resource-server.js';

const generateToken = async ({
  issuer,
  payload,
  alg = 'ES256',
  jwksPath = '/oauth/jwks',
}: {
  issuer: string;
  payload: Record<string, unknown>;
  alg?: string;
  jwksPath?: string;
}) => {
  const { privateKey, publicKey } = await generateKeyPair(alg);
  const jwks = nock(issuer)
    .get(jwksPath)
    .reply(200, {
      keys: [await exportJWK(publicKey)],
    });

  const token = await new SignJWT(payload)
    .setProtectedHeader({ alg })
    .setIssuedAt()
    .setExpirationTime('1h')
    .sign(privateKey);

  return { token, jwks };
};

afterEach(() => {
  nock.cleanAll();
});

describe('MCP Server as authorization server', () => {
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
    } satisfies AuthServerModeConfig['server']['metadata']);

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
    } satisfies AuthServerModeConfig['server']['metadata']);

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
      const { token: validToken, jwks } = await generateToken({
        issuer: metadata.issuer,
        payload: {
          iss: metadata.issuer,
          aud: audience,
          client_id: 'client12345',
          sub: 'user12345',
        },
      });
      await request(createApp()).get('/').set('Authorization', `Bearer ${validToken}`).expect(403);
      expect(jwks.isDone()).toBe(true);
    });

    it('should return 200 if the token is valid and has required scopes', async () => {
      const { token: validToken, jwks } = await generateToken({
        issuer: metadata.issuer,
        payload: {
          iss: metadata.issuer,
          aud: audience,
          client_id: 'client12345',
          sub: 'user12345',
          scope: ['read', 'write'].join(' '),
        },
      });
      await request(createApp()).get('/').set('Authorization', `Bearer ${validToken}`).expect(200);
      expect(jwks.isDone()).toBe(true);
    });
  });
});

describe('MCP Server as resource server', () => {
  const resource1 = 'https://api.example.com/resource1';
  const resource2 = 'https://api.example.com/resource2';

  const authServer1: AuthServerConfig = {
    metadata: {
      issuer: 'https://auth1.example.com',
      authorizationEndpoint: 'https://auth1.example.com/oauth/authorize',
      tokenEndpoint: 'https://auth1.example.com/oauth/token',
      jwksUri: 'https://auth1.example.com/oauth/jwks',
      responseTypesSupported: ['code'],
      grantTypesSupported: ['authorization_code'],
      codeChallengeMethodsSupported: ['S256'],
    },
    type: 'oauth',
  };

  const authServer2: AuthServerConfig = {
    type: 'oauth',
    metadata: {
      issuer: 'https://auth2.example.com',
      authorizationEndpoint: 'https://auth2.example.com/oauth/authorize',
      tokenEndpoint: 'https://auth2.example.com/oauth/token',
      jwksUri: 'https://auth2.example.com/oauth/jwks',
      responseTypesSupported: ['code'],
      grantTypesSupported: ['authorization_code'],
      codeChallengeMethodsSupported: ['S256'],
    },
  };

  const resourceServerConfig1: ResourceServerConfig = {
    metadata: {
      resource: resource1,
      authorizationServers: [authServer1],
      scopesSupported: ['read:resource1', 'write:resource1'],
    },
  };

  const resourceServerConfig2 = {
    metadata: {
      resource: resource2,
      authorizationServers: [authServer2],
      scopesSupported: ['read:resource2', 'write:resource2'],
    },
  };

  describe('MCPAuth class (constructor)', () => {
    it('should throw an error for duplicate resource identifiers', () => {
      expect(
        () =>
          new MCPAuth({
            protectedResource: [resourceServerConfig1, resourceServerConfig1],
          })
      ).toThrow('The server configuration does not match the MCP specification.');
    });

    it('should throw an error for duplicate authorization servers for a resource', () => {
      expect(
        () =>
          new MCPAuth({
            protectedResource: {
              metadata: {
                resource: resource1,
                authorizationServers: [authServer1, authServer1],
              },
            },
          })
      ).toThrow('The server configuration does not match the MCP specification.');
    });
  });

  describe('MCPAuth class (protectedResourceMetadataRouter)', () => {
    it('should serve metadata for a single resource', async () => {
      const auth = new MCPAuth({
        protectedResource: resourceServerConfig1,
      });
      const app = express();
      app.use(auth.protectedResourceMetadataRouter());

      const rawMetadata = {
        resource: resource1,
        authorizationServers: [authServer1.metadata.issuer],
        scopesSupported: ['read:resource1', 'write:resource1'],
      };

      await request(app)
        .get(`/.well-known/oauth-protected-resource${new URL(resource1).pathname}`)
        .expect(200, snakecaseKeys(rawMetadata));
    });

    it('should serve metadata for multiple resources', async () => {
      const auth = new MCPAuth({
        protectedResource: [resourceServerConfig1, resourceServerConfig2],
      });
      const app = express();
      app.use(auth.protectedResourceMetadataRouter());

      const rawMetadata1 = {
        resource: resource1,
        authorizationServers: [authServer1.metadata.issuer],
        scopesSupported: ['read:resource1', 'write:resource1'],
      };

      await request(app)
        .get(`/.well-known/oauth-protected-resource${new URL(resource1).pathname}`)
        .expect(200, snakecaseKeys(rawMetadata1));

      const rawMetadata2 = {
        resource: resource2,
        authorizationServers: [authServer2.metadata.issuer],
        scopesSupported: ['read:resource2', 'write:resource2'],
      };

      await request(app)
        .get(`/.well-known/oauth-protected-resource${new URL(resource2).pathname}`)
        .expect(200, snakecaseKeys(rawMetadata2));
    });
  });

  describe('MCPAuth class (bearerAuth)', () => {
    const path1 = new URL(resource1).pathname;
    const path2 = new URL(resource2).pathname;

    const createApp = (auth: MCPAuth) => {
      const app = express();
      app.get(
        path1,
        auth.bearerAuth('jwt', {
          resource: resource1,
          audience: resource1,
          requiredScopes: ['read:resource1'],
        }),
        (_, response) => {
          response.status(200).send(`Success ${path1}`);
        }
      );
      app.get(
        path2,
        auth.bearerAuth('jwt', {
          resource: resource2,
          audience: resource2,
          requiredScopes: ['read:resource2'],
        }),
        (_, response) => {
          response.status(200).send(`Success ${path2}`);
        }
      );
      return app;
    };

    it('should throw an error if resource is not specified in bearerAuth config', () => {
      const auth = new MCPAuth({
        protectedResource: resourceServerConfig1,
      });
      expect(() => auth.bearerAuth('jwt')).toThrow(
        'The server configuration does not match the MCP specification.'
      );
    });

    it('should throw an error for a non-configured resource', () => {
      const auth = new MCPAuth({
        protectedResource: resourceServerConfig1,
      });
      expect(() => auth.bearerAuth('jwt', { resource: 'https://api.example.com/unknown' })).toThrow(
        'The server configuration does not match the MCP specification.'
      );
    });

    it('should return 200 for resource 1 with a valid token', async () => {
      const auth = new MCPAuth({
        protectedResource: [resourceServerConfig1, resourceServerConfig2],
      });
      const app = createApp(auth);
      const { token, jwks } = await generateToken({
        issuer: authServer1.metadata.issuer,
        payload: {
          iss: authServer1.metadata.issuer,
          aud: resource1,
          scope: 'read:resource1',
          sub: 'user12345',
        },
      });

      console.log('token for resource1', token);

      await request(app)
        .get(path1)
        .set('Authorization', `Bearer ${token}`)
        .expect(200, `Success ${path1}`);
      expect(jwks.isDone()).toBe(true);
    });

    it('should return 403 for resource 1 when token is missing scopes', async () => {
      const auth = new MCPAuth({
        protectedResource: [resourceServerConfig1, resourceServerConfig2],
      });
      const app = createApp(auth);
      const { token, jwks } = await generateToken({
        issuer: authServer1.metadata.issuer,
        payload: {
          iss: authServer1.metadata.issuer,
          aud: resource1,
          scope: 'write:resource1',
          sub: 'user12345',
        },
      });

      await request(app).get(path1).set('Authorization', `Bearer ${token}`).expect(403);
      expect(jwks.isDone()).toBe(true);
    });

    it('should return 401 for resource 1 when token is for resource 2', async () => {
      const auth = new MCPAuth({
        protectedResource: [resourceServerConfig1, resourceServerConfig2],
      });
      const app = createApp(auth);
      // Token from auth server 2 for resource 2
      const { token, jwks } = await generateToken({
        issuer: authServer2.metadata.issuer,
        payload: {
          iss: authServer2.metadata.issuer,
          aud: resource2,
          scope: 'read:resource2',
          sub: 'user12345',
        },
      });

      // Trying to access resource 1
      await request(app).get(path1).set('Authorization', `Bearer ${token}`).expect(401);
      // JWKS from auth server 2 should not have been requested
      expect(jwks.isDone()).toBe(false);
    });

    it('should return 200 for resource 2 with a valid token', async () => {
      const auth = new MCPAuth({
        protectedResource: [resourceServerConfig1, resourceServerConfig2],
      });
      const app = createApp(auth);
      const { token, jwks } = await generateToken({
        issuer: authServer2.metadata.issuer,
        payload: {
          iss: authServer2.metadata.issuer,
          aud: resource2,
          scope: 'read:resource2',
          sub: 'user12345',
        },
      });

      await request(app)
        .get(path2)
        .set('Authorization', `Bearer ${token}`)
        .expect(200, `Success ${path2}`);
      expect(jwks.isDone()).toBe(true);
    });
  });
});
