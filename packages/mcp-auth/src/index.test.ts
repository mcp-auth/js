import { bearerAuthChallengeResponse, verifyBearerToken } from '@modelcontextprotocol/server';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import nock from 'nock';
import { afterEach, describe, expect, it } from 'vitest';

import {
  fetchServerConfig,
  fetchServerConfigByWellKnownUrl,
  getAuthInfo,
  isMcpAuthInfo,
  MCPAuth,
  MCPAuthAuthServerError,
  MCPAuthConfigError,
  MCPAuthError,
} from './index.js';

describe('public API surface', () => {
  it('should export the documented API', () => {
    expect(MCPAuth).toBeTypeOf('function');
    expect(getAuthInfo).toBeTypeOf('function');
    expect(isMcpAuthInfo).toBeTypeOf('function');
    expect(fetchServerConfig).toBeTypeOf('function');
    expect(fetchServerConfigByWellKnownUrl).toBeTypeOf('function');
    expect(MCPAuthError).toBeTypeOf('function');
    expect(MCPAuthConfigError).toBeTypeOf('function');
    expect(MCPAuthAuthServerError).toBeTypeOf('function');
  });
});

describe('integration with the MCP SDK bearer-auth helpers', () => {
  const issuer = 'https://auth.example.com';
  const resource = 'https://api.example.com/mcp';

  const metadata = Object.freeze({
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    jwks_uri: `${issuer}/jwks`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code'],
    code_challenge_methods_supported: ['S256'],
    registration_endpoint: `${issuer}/register`,
  });

  afterEach(() => {
    nock.cleanAll();
  });

  it('should verify a Bearer token end-to-end and refuse an invalid one with a 401 challenge', async () => {
    const { privateKey, publicKey } = await generateKeyPair('ES256');
    nock(issuer)
      .get('/jwks')
      .reply(200, { keys: [await exportJWK(publicKey)] });

    const mcpAuth = new MCPAuth({
      resource,
      authorizationServer: { type: 'oidc', metadata },
    });

    const token = await new SignJWT({ iss: issuer, sub: 'user-1', aud: resource, scope: 'read' })
      .setProtectedHeader({ alg: 'ES256' })
      .setIssuedAt()
      .setExpirationTime('1h')
      .sign(privateKey);

    const authInfo = await verifyBearerToken(`Bearer ${token}`, {
      verifier: mcpAuth,
      requiredScopes: ['read'],
    });
    expect(isMcpAuthInfo(authInfo)).toBe(true);
    expect(authInfo).toMatchObject({ clientId: '', scopes: ['read'] });

    /*
     * The SDK maps the `OAuthError` thrown by `verifyAccessToken` to a `401` response with a
     * `WWW-Authenticate` challenge pointing at the Protected Resource Metadata.
     */
    const error = await verifyBearerToken('Bearer invalid-token', { verifier: mcpAuth }).then(
      () => {
        throw new Error('Expected the promise to reject.');
      },
      (error: unknown) => error
    );
    const response = bearerAuthChallengeResponse(error, {
      resourceMetadataUrl: mcpAuth.resourceMetadataUrl,
    });

    expect(response.status).toBe(401);
    expect(response.headers.get('WWW-Authenticate')).toContain('Bearer error="invalid_token"');
    expect(response.headers.get('WWW-Authenticate')).toContain(
      'resource_metadata="https://api.example.com/.well-known/oauth-protected-resource/mcp"'
    );
  });
});
