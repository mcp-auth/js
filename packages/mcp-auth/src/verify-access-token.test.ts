import { OAuthError, OAuthErrorCode } from '@modelcontextprotocol/server';
import { exportJWK, generateKeyPair, SignJWT, type CryptoKey, type JWK } from 'jose';
import nock from 'nock';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';

import { MCPAuthConfigError } from './errors.js';
import { MCPAuth } from './mcp-auth.js';
import { matchError } from './test-utils.js';
import { type AuthServerMetadata } from './types.js';

const issuer = 'https://auth.example.com';
const resource = 'https://api.example.com/mcp';
const jwksPath = '/jwks';
const alg = 'ES256';

const metadata: AuthServerMetadata = Object.freeze({
  issuer,
  authorization_endpoint: `${issuer}/authorize`,
  token_endpoint: `${issuer}/token`,
  jwks_uri: `${issuer}${jwksPath}`,
  response_types_supported: ['code'],
  grant_types_supported: ['authorization_code'],
  code_challenge_methods_supported: ['S256'],
  registration_endpoint: `${issuer}/register`,
});

/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation -- initialized once in `beforeAll` */
let privateKey: CryptoKey;
let publicJwk: JWK;

beforeAll(async () => {
  const keyPair = await generateKeyPair(alg);
  privateKey = keyPair.privateKey;
  publicJwk = await exportJWK(keyPair.publicKey);
});
/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation */

const mockJwks = (times = 1) =>
  nock(issuer)
    .get(jwksPath)
    .times(times)
    .reply(200, { keys: [publicJwk] });

type CreateTokenOptions = {
  expiresAt?: number;
  signKey?: CryptoKey;
};

const createToken = async (
  payload: Record<string, unknown>,
  { expiresAt, signKey }: CreateTokenOptions = {}
) => {
  const jwt = new SignJWT(payload).setProtectedHeader({ alg }).setIssuedAt();

  if (expiresAt !== undefined) {
    jwt.setExpirationTime(expiresAt);
  }

  return jwt.sign(signKey ?? privateKey);
};

const oneHourFromNow = () => Math.floor(Date.now() / 1000) + 3600;

const createMcpAuth = (configOverrides: Partial<ConstructorParameters<typeof MCPAuth>[0]> = {}) =>
  new MCPAuth({
    protectedResourceMetadata: { resource, authorizationServer: { type: 'oidc', metadata } },
    ...configOverrides,
  });

const createValidToken = async () =>
  createToken({ iss: issuer, sub: 'user-1', aud: resource }, { expiresAt: oneHourFromNow() });

const verifyPayload = async (payload: Record<string, unknown>) => {
  mockJwks();
  const mcpAuth = createMcpAuth();
  const token = await createToken(
    { iss: issuer, sub: 'user-1', aud: resource, ...payload },
    { expiresAt: oneHourFromNow() }
  );
  return mcpAuth.verifyAccessToken(token);
};

const expectOAuthError = async (promise: Promise<unknown>, messagePart: string) => {
  const error = await promise.then(
    () => {
      throw new Error('Expected the promise to reject.');
    },
    (error: unknown) => error
  );

  expect(error).toBeInstanceOf(OAuthError);
  expect(error).toHaveProperty('code', OAuthErrorCode.InvalidToken);
  expect(error).toHaveProperty('message', expect.stringContaining(messagePart));
};

afterEach(() => {
  nock.cleanAll();
});

describe('MCPAuth verifyAccessToken (pre-checks)', () => {
  it('should reject a malformed token before any network request', async () => {
    const mcpAuth = createMcpAuth();

    await expectOAuthError(
      mcpAuth.verifyAccessToken('not-a-jwt'),
      'The JWT is malformed or invalid.'
    );
    expect(nock.pendingMocks()).toEqual([]);
  });

  it('should reject a token without an `iss` claim', async () => {
    const mcpAuth = createMcpAuth();
    const token = await createToken({ sub: 'user-1' }, { expiresAt: oneHourFromNow() });

    await expectOAuthError(mcpAuth.verifyAccessToken(token), 'does not contain the `iss` field');
  });

  it('should reject a token from an untrusted issuer before fetching metadata or JWKS', async () => {
    const wellKnown = nock(issuer).get('/.well-known/openid-configuration').reply(200, metadata);
    const jwks = mockJwks();
    const mcpAuth = new MCPAuth({
      protectedResourceMetadata: { resource, authorizationServer: { issuer, type: 'oidc' } },
    });
    const token = await createToken(
      { iss: 'https://evil.example.com', sub: 'user-1', aud: resource },
      { expiresAt: oneHourFromNow() }
    );

    await expectOAuthError(mcpAuth.verifyAccessToken(token), 'is not trusted');
    expect(wellKnown.isDone()).toBe(false);
    expect(jwks.isDone()).toBe(false);
  });
});

describe('MCPAuth verifyAccessToken (JWT verification)', () => {
  it('should verify a valid token and return the extended auth info', async () => {
    mockJwks();
    const mcpAuth = createMcpAuth();
    const expiresAt = oneHourFromNow();
    const token = await createToken(
      { iss: issuer, sub: 'user-1', aud: resource, client_id: 'client-1', scope: 'read write' },
      { expiresAt }
    );

    const { claims, ...authInfo } = await mcpAuth.verifyAccessToken(token);

    expect(authInfo).toEqual({
      token,
      issuer,
      subject: 'user-1',
      clientId: 'client-1',
      scopes: ['read', 'write'],
      expiresAt,
    });
    expect(claims).toMatchObject({ iss: issuer, sub: 'user-1', aud: resource });
  });

  it('should reject a token with an invalid signature', async () => {
    mockJwks();
    const mcpAuth = createMcpAuth();
    const { privateKey: wrongKey } = await generateKeyPair(alg);
    const token = await createToken(
      { iss: issuer, sub: 'user-1', aud: resource },
      { expiresAt: oneHourFromNow(), signKey: wrongKey }
    );

    await expectOAuthError(
      mcpAuth.verifyAccessToken(token),
      'ERR_JWS_SIGNATURE_VERIFICATION_FAILED'
    );
  });

  it('should reject an expired token', async () => {
    mockJwks();
    const mcpAuth = createMcpAuth();
    const token = await createToken(
      { iss: issuer, sub: 'user-1', aud: resource },
      { expiresAt: Math.floor(Date.now() / 1000) - 3600 }
    );

    await expectOAuthError(mcpAuth.verifyAccessToken(token), 'ERR_JWT_EXPIRED');
  });

  it('should reject a token without a `sub` claim', async () => {
    mockJwks();
    const mcpAuth = createMcpAuth();
    const token = await createToken(
      { iss: issuer, aud: resource },
      { expiresAt: oneHourFromNow() }
    );

    await expectOAuthError(mcpAuth.verifyAccessToken(token), 'does not contain the `sub` field');
  });

  it('should leave `expiresAt` unset for a token without an `exp` claim', async () => {
    mockJwks();
    const mcpAuth = createMcpAuth();
    const token = await createToken({ iss: issuer, sub: 'user-1', aud: resource });

    /*
     * The SDK bearer-auth helpers reject auth info without `expiresAt`, so such tokens are
     * still refused at the HTTP layer.
     */
    const { expiresAt } = await mcpAuth.verifyAccessToken(token);
    expect(expiresAt).toBeUndefined();
  });

  it('should surface non-JOSE verification errors with a generic message', async () => {
    /* No JWKS endpoint is mocked, so the JWKS fetch fails with a (non-JOSE) network error. */
    nock.disableNetConnect();
    const mcpAuth = createMcpAuth();

    await expectOAuthError(
      mcpAuth.verifyAccessToken(await createValidToken()),
      'Failed to verify the access token.'
    );
    nock.enableNetConnect();
  });

  it('should reuse the remote JWK Set instance across verifications', async () => {
    // A single JWKS response is mocked; a second HTTP request would fail.
    mockJwks();
    const mcpAuth = createMcpAuth();

    await expect(mcpAuth.verifyAccessToken(await createValidToken())).resolves.toBeTruthy();
    await expect(mcpAuth.verifyAccessToken(await createValidToken())).resolves.toBeTruthy();
    expect(nock.pendingMocks()).toEqual([]);
  });
});

describe('MCPAuth verifyAccessToken (audience validation)', () => {
  it('should reject a token whose `aud` does not match the resource', async () => {
    mockJwks();
    const mcpAuth = createMcpAuth();
    const token = await createToken(
      { iss: issuer, sub: 'user-1', aud: 'https://another.example.com' },
      { expiresAt: oneHourFromNow() }
    );

    await expectOAuthError(mcpAuth.verifyAccessToken(token), 'ERR_JWT_CLAIM_VALIDATION_FAILED');
  });

  it('should reject a token without an `aud` claim', async () => {
    mockJwks();
    const mcpAuth = createMcpAuth();
    const token = await createToken(
      { iss: issuer, sub: 'user-1' },
      { expiresAt: oneHourFromNow() }
    );

    await expectOAuthError(mcpAuth.verifyAccessToken(token), 'ERR_JWT_CLAIM_VALIDATION_FAILED');
  });

  it('should accept a token whose `aud` array contains the resource', async () => {
    mockJwks();
    const mcpAuth = createMcpAuth();
    const token = await createToken(
      { iss: issuer, sub: 'user-1', aud: [resource, 'https://another.example.com'] },
      { expiresAt: oneHourFromNow() }
    );

    await expect(mcpAuth.verifyAccessToken(token)).resolves.toHaveProperty('subject', 'user-1');
  });

  it('should not allow overriding the audience via `jwtVerifyOptions`', async () => {
    mockJwks();
    /*
     * Audience validation always expects the `resource` identifier (RFC 8707). The `audience`
     * option is excluded from `jwtVerifyOptions` at the type level; prove the runtime guard
     * holds even when the types are bypassed.
     */
    const mcpAuth = createMcpAuth({
      jwtVerifyOptions: {
        // @ts-expect-error -- deliberately bypass the types to prove the runtime guard
        audience: 'https://evil.example.com',
      },
    });
    const token = await createToken(
      { iss: issuer, sub: 'user-1', aud: 'https://evil.example.com' },
      { expiresAt: oneHourFromNow() }
    );

    await expectOAuthError(mcpAuth.verifyAccessToken(token), 'ERR_JWT_CLAIM_VALIDATION_FAILED');
  });
});

describe('MCPAuth verifyAccessToken (claim mapping)', () => {
  it('should fall back to the `azp` claim for the client ID', async () => {
    await expect(verifyPayload({ azp: 'azp-client' })).resolves.toHaveProperty(
      'clientId',
      'azp-client'
    );
  });

  it('should prefer `client_id` over `azp`', async () => {
    await expect(
      verifyPayload({ client_id: 'client-1', azp: 'azp-client' })
    ).resolves.toHaveProperty('clientId', 'client-1');
  });

  it('should default the client ID to an empty string', async () => {
    await expect(verifyPayload({})).resolves.toHaveProperty('clientId', '');
  });

  it('should read scopes from the `scopes` array claim', async () => {
    await expect(verifyPayload({ scopes: ['read', 'write'] })).resolves.toHaveProperty('scopes', [
      'read',
      'write',
    ]);
  });

  it('should prefer the `scope` claim over the `scopes` claim', async () => {
    await expect(verifyPayload({ scope: 'read', scopes: ['write'] })).resolves.toHaveProperty(
      'scopes',
      ['read']
    );
  });

  it('should default scopes to an empty array', async () => {
    await expect(verifyPayload({})).resolves.toHaveProperty('scopes', []);
  });
});

describe('MCPAuth verifyAccessToken (jose overrides)', () => {
  it('should apply custom `jwtVerifyOptions`', async () => {
    mockJwks();
    const mcpAuth = createMcpAuth({ jwtVerifyOptions: { requiredClaims: ['custom_claim'] } });
    const token = await createToken(
      { iss: issuer, sub: 'user-1', aud: resource },
      { expiresAt: oneHourFromNow() }
    );

    await expectOAuthError(mcpAuth.verifyAccessToken(token), 'ERR_JWT_CLAIM_VALIDATION_FAILED');
  });

  it('should not allow overriding the issuer via `jwtVerifyOptions`', async () => {
    mockJwks();
    const mcpAuth = createMcpAuth({
      jwtVerifyOptions: {
        // @ts-expect-error -- deliberately bypass the types to prove the runtime guard
        issuer: 'https://evil.example.com',
      },
    });
    const token = await createToken(
      { iss: issuer, sub: 'user-1', aud: resource },
      { expiresAt: oneHourFromNow() }
    );

    await expect(mcpAuth.verifyAccessToken(token)).resolves.toHaveProperty('issuer', issuer);
  });
});

describe('MCPAuth verifyAccessToken (discovery)', () => {
  const discoveryConfig = Object.freeze({
    protectedResourceMetadata: { resource, authorizationServer: { issuer, type: 'oidc' } },
  } as const);

  it('should fetch the metadata once and verify tokens', async () => {
    const wellKnown = nock(issuer).get('/.well-known/openid-configuration').reply(200, metadata);
    mockJwks();
    const mcpAuth = new MCPAuth(discoveryConfig);

    await expect(mcpAuth.verifyAccessToken(await createValidToken())).resolves.toBeTruthy();
    await expect(mcpAuth.verifyAccessToken(await createValidToken())).resolves.toBeTruthy();
    expect(wellKnown.isDone()).toBe(true);
    expect(nock.pendingMocks()).toEqual([]);
  });

  it('should share a single discovery fetch across concurrent verifications', async () => {
    const wellKnown = nock(issuer).get('/.well-known/openid-configuration').reply(200, metadata);
    mockJwks();
    const mcpAuth = new MCPAuth(discoveryConfig);
    const [token1, token2] = await Promise.all([createValidToken(), createValidToken()]);

    const results = await Promise.all([
      mcpAuth.verifyAccessToken(token1),
      mcpAuth.verifyAccessToken(token2),
    ]);

    expect(results).toHaveLength(2);
    expect(wellKnown.isDone()).toBe(true);
    expect(nock.pendingMocks()).toEqual([]);
  });

  it('should recover after a transient discovery failure', async () => {
    nock(issuer).get('/.well-known/openid-configuration').reply(500, 'Internal Server Error');
    const mcpAuth = new MCPAuth(discoveryConfig);
    const token = await createValidToken();

    await expect(mcpAuth.verifyAccessToken(token)).rejects.toThrowError(MCPAuthConfigError);

    nock(issuer).get('/.well-known/openid-configuration').reply(200, metadata);
    mockJwks();
    await expect(mcpAuth.verifyAccessToken(token)).resolves.toHaveProperty('subject', 'user-1');
  });

  it('should reject if the fetched metadata issuer does not match', async () => {
    nock(issuer)
      .get('/.well-known/openid-configuration')
      .reply(200, { ...metadata, issuer: 'https://another.example.com' });
    const mcpAuth = new MCPAuth(discoveryConfig);

    await expect(mcpAuth.verifyAccessToken(await createValidToken())).rejects.toThrowError(
      matchError('MCPAuthAuthServerError', 'invalid_server_metadata')
    );
  });

  it('should reject if the fetched metadata does not satisfy the MCP specification', async () => {
    const { code_challenge_methods_supported: _removed, ...invalidMetadata } = metadata;
    nock(issuer).get('/.well-known/openid-configuration').reply(200, invalidMetadata);
    const mcpAuth = new MCPAuth(discoveryConfig);

    await expect(mcpAuth.verifyAccessToken(await createValidToken())).rejects.toThrowError(
      matchError('MCPAuthAuthServerError', 'invalid_server_config')
    );
  });

  it('should reject if the metadata has no JWKS URI', async () => {
    const { jwks_uri: _removed, ...withoutJwks } = metadata;
    nock(issuer).get('/.well-known/openid-configuration').reply(200, withoutJwks);
    const mcpAuth = new MCPAuth(discoveryConfig);

    await expect(mcpAuth.verifyAccessToken(await createValidToken())).rejects.toThrowError(
      matchError('MCPAuthAuthServerError', 'missing_jwks_uri')
    );
  });
});
