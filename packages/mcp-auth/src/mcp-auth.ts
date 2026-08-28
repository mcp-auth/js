import {
  getOAuthProtectedResourceMetadataUrl,
  OAuthError,
  OAuthErrorCode,
  type AuthMetadataOptions,
  type OAuthTokenVerifier,
} from '@modelcontextprotocol/server';
import {
  decodeJwt,
  jwtVerify,
  type JWTPayload,
  type JWTVerifyGetKey,
  type JWTVerifyOptions,
  type RemoteJWKSetOptions,
} from 'jose';
import { JOSEError } from 'jose/errors';

import { type McpAuthInfo } from './auth-info.js';
import { AuthServerContext } from './auth-server-context.js';
import { MCPAuthConfigError } from './errors.js';
import { type AuthServerConfig } from './types.js';
import { parseAuthServerMetadata, validateResolvedMetadata } from './validate-auth-server.js';

/**
 * Config for the {@link MCPAuth} class. One instance protects one resource and trusts one
 * authorization server.
 */
export type MCPAuthConfig = {
  /**
   * The resource identifier of this MCP server (RFC 8707), e.g. `https://api.example.com/mcp`.
   *
   * It is used as the `resource` value in the Protected Resource Metadata document, as the
   * default expected `aud` (audience) claim of access tokens, and to build
   * {@link MCPAuth.resourceMetadataUrl}.
   */
  resource: string;
  /**
   * The authorization server trusted by this MCP server. Either a discovery config
   * (`{ issuer, type }`, metadata fetched lazily on first use) or a resolved config with
   * metadata — hardcoded or pre-fetched via {@link fetchServerConfig}.
   *
   * @see {@link AuthServerConfig} for the two variants.
   */
  authorizationServer: AuthServerConfig;
  /**
   * The scopes this MCP server understands, advertised as `scopes_supported` in the Protected
   * Resource Metadata document.
   */
  scopesSupported?: string[];
  /**
   * A human-readable name for this MCP server, advertised as `resource_name` in the Protected
   * Resource Metadata document.
   */
  resourceName?: string;
  /**
   * A documentation URL for this MCP server, advertised as `resource_documentation` in the
   * Protected Resource Metadata document.
   */
  serviceDocumentationUrl?: string;
  /**
   * The expected `aud` (audience) claim of access tokens. Defaults to {@link resource}.
   *
   * Set to `false` to disable audience validation, for providers that do not include an `aud`
   * claim in their access tokens. Only do this when you understand the implications: without
   * audience validation, a token issued for a different resource of the same authorization
   * server will be accepted by this MCP server.
   */
  audience?: string | false;
  /**
   * Per-call options passed to the underlying `jose.jwtVerify` function, e.g. `clockTolerance`
   * or `requiredClaims`. The `issuer` option (and the `audience` option, unless
   * {@link audience} is `false`) is always set by mcp-auth and cannot be overridden here.
   *
   * @see {@link JWTVerifyOptions}
   */
  jwtVerify?: JWTVerifyOptions;
  /**
   * Options passed to the underlying `jose.createRemoteJWKSet` function, e.g. `cacheMaxAge` or
   * custom headers for the JWKS request.
   *
   * @see {@link RemoteJWKSetOptions}
   */
  remoteJwkSet?: RemoteJWKSetOptions;
};

const getScopes = (value: unknown): string[] | undefined => {
  if (Array.isArray(value)) {
    return value.filter((item): item is string => typeof item === 'string');
  }
  if (typeof value === 'string') {
    return value.split(' ').filter((item) => item.trim() !== '');
  }
};

const decodeJwtPayload = (token: string): JWTPayload | undefined => {
  try {
    return decodeJwt(token);
  } catch {
    return undefined;
  }
};

/**
 * Decodes the JWT to extract its issuer without verifying the signature, so malformed and
 * untrusted tokens are rejected before any metadata or JWKS request.
 */
const getUnverifiedJwtIssuer = (token: string): string => {
  const payload = decodeJwtPayload(token);

  if (!payload) {
    throw new OAuthError(OAuthErrorCode.InvalidToken, 'The JWT is malformed or invalid.');
  }

  const { iss } = payload;

  if (typeof iss !== 'string' || !iss) {
    throw new OAuthError(
      OAuthErrorCode.InvalidToken,
      'The JWT payload does not contain the `iss` field or it is malformed.'
    );
  }

  return iss;
};

const assertValidUrl = (value: string, name: string) => {
  if (!URL.canParse(value)) {
    throw new MCPAuthConfigError(
      'invalid_config',
      `The \`${name}\` (\`${value}\`) is not a valid URL.`
    );
  }
};

/**
 * The main class of the mcp-auth library, providing the two inputs the MCP TypeScript SDK asks
 * you to bring when protecting an MCP server:
 *
 * 1. **A token verifier** — the instance itself implements the SDK's `OAuthTokenVerifier`
 *    interface, so it can be passed directly as the `verifier` to the SDK's `requireBearerAuth`
 *    (or any of its framework adapters).
 * 2. **Your auth metadata** — {@link getAuthMetadataOptions} returns the SDK's
 *    `AuthMetadataOptions`, ready to feed to `oauthMetadataResponse` (fetch-native) or
 *    `mcpAuthMetadataRouter` (from `@modelcontextprotocol/express`).
 *
 * One instance represents one protected resource trusting one authorization server. Create
 * multiple instances if your deployment serves multiple resources.
 *
 * @example
 * ### Fetch-native runtimes (Cloudflare Workers, Deno, Bun, Node.js)
 *
 * ```ts
 * import { createMcpHandler, McpServer, oauthMetadataResponse, requireBearerAuth } from '@modelcontextprotocol/server';
 * import { getAuthInfo, MCPAuth } from 'mcp-auth';
 *
 * const mcpAuth = new MCPAuth({
 *   resource: 'https://api.example.com/mcp',
 *   authorizationServer: { issuer: 'https://auth.example.com/oidc', type: 'oidc' },
 *   scopesSupported: ['read:notes'],
 * });
 *
 * const server = new McpServer({ name: 'Notes', version: '1.0.0' });
 * server.registerTool('whoami', { description: 'Get the current user' }, (ctx) => {
 *   const { subject, claims } = getAuthInfo(ctx);
 *   return { content: [{ type: 'text', text: JSON.stringify({ subject, claims }) }] };
 * });
 *
 * const handler = createMcpHandler(server);
 * const gate = requireBearerAuth({
 *   verifier: mcpAuth,
 *   requiredScopes: ['read:notes'],
 *   resourceMetadataUrl: mcpAuth.resourceMetadataUrl,
 * });
 *
 * export default {
 *   async fetch(request: Request): Promise<Response> {
 *     // Serve the OAuth discovery documents (`/.well-known/...`)
 *     const metadataResponse = oauthMetadataResponse(request, await mcpAuth.getAuthMetadataOptions());
 *     if (metadataResponse) {
 *       return metadataResponse;
 *     }
 *
 *     // Require a valid Bearer token for everything else
 *     const auth = await gate(request);
 *     if (auth instanceof Response) {
 *       return auth;
 *     }
 *
 *     return handler.fetch(request, { authInfo: auth });
 *   },
 * };
 * ```
 *
 * ### Express (via `@modelcontextprotocol/express`)
 *
 * ```ts
 * import { mcpAuthMetadataRouter, requireBearerAuth } from '@modelcontextprotocol/express';
 * import { NodeStreamableHTTPServerTransport } from '@modelcontextprotocol/node';
 * import express from 'express';
 * import { MCPAuth } from 'mcp-auth';
 *
 * const mcpAuth = new MCPAuth({
 *   resource: 'https://api.example.com/mcp',
 *   authorizationServer: { issuer: 'https://auth.example.com/oidc', type: 'oidc' },
 *   scopesSupported: ['read:notes'],
 * });
 *
 * const app = express();
 * app.use(express.json());
 * app.use(mcpAuthMetadataRouter(await mcpAuth.getAuthMetadataOptions()));
 * app.post(
 *   '/mcp',
 *   requireBearerAuth({
 *     verifier: mcpAuth,
 *     requiredScopes: ['read:notes'],
 *     resourceMetadataUrl: mcpAuth.resourceMetadataUrl,
 *   }),
 *   async (request, response) => {
 *     const transport = new NodeStreamableHTTPServerTransport({ sessionIdGenerator: undefined });
 *     await server.connect(transport);
 *     await transport.handleRequest(request, response, request.body);
 *   }
 * );
 * ```
 */
export class MCPAuth implements OAuthTokenVerifier {
  readonly #authServer: AuthServerContext;

  /**
   * Creates an instance of MCPAuth and validates the configuration, so misconfigurations fail
   * fast at startup. For a resolved authorization server config, the metadata is validated
   * immediately; for a discovery config, the metadata is validated when it is first fetched.
   *
   * @param config The authentication configuration.
   * @throws {MCPAuthConfigError} if the configuration is malformed.
   * @throws {MCPAuthAuthServerError} if the provided authorization server metadata is invalid
   * or does not satisfy the MCP authorization specification.
   */
  constructor(public readonly config: MCPAuthConfig) {
    const { resource, authorizationServer, serviceDocumentationUrl, audience } = config;

    if (!resource) {
      throw new MCPAuthConfigError('invalid_config', 'A `resource` identifier is required.');
    }
    assertValidUrl(resource, 'resource');

    if ('metadata' in authorizationServer) {
      validateResolvedMetadata(parseAuthServerMetadata(authorizationServer.metadata));
    } else {
      if (!authorizationServer.issuer) {
        throw new MCPAuthConfigError(
          'invalid_config',
          'An `authorizationServer.issuer` is required for discovery configs.'
        );
      }
      assertValidUrl(authorizationServer.issuer, 'authorizationServer.issuer');
    }

    if (serviceDocumentationUrl !== undefined) {
      assertValidUrl(serviceDocumentationUrl, 'serviceDocumentationUrl');
    }

    if (audience !== undefined && audience !== false && !audience) {
      throw new MCPAuthConfigError(
        'invalid_config',
        'The `audience` must be a non-empty string, or `false` to disable audience validation.'
      );
    }

    this.#authServer = new AuthServerContext(authorizationServer, config.remoteJwkSet);
  }

  /**
   * The RFC 9728 Protected Resource Metadata URL for the configured {@link MCPAuthConfig.resource},
   * built with the MCP SDK's `getOAuthProtectedResourceMetadataUrl`.
   *
   * Pass it as the `resourceMetadataUrl` option of the SDK's `requireBearerAuth` so the
   * `WWW-Authenticate` challenge on `401` responses points clients at the metadata document.
   *
   * @example
   * ```ts
   * const mcpAuth = new MCPAuth({ resource: 'https://api.example.com/mcp', ... });
   * mcpAuth.resourceMetadataUrl
   * // → 'https://api.example.com/.well-known/oauth-protected-resource/mcp'
   * ```
   */
  get resourceMetadataUrl(): string {
    return getOAuthProtectedResourceMetadataUrl(new URL(this.config.resource));
  }

  /**
   * Builds the MCP SDK's `AuthMetadataOptions` from this instance's configuration and the
   * (possibly lazily fetched) authorization server metadata.
   *
   * Feed the result to the SDK's `oauthMetadataResponse` (fetch-native) or to
   * `mcpAuthMetadataRouter` from `@modelcontextprotocol/express` to serve the OAuth discovery
   * documents (RFC 9728 Protected Resource Metadata and RFC 8414 Authorization Server Metadata).
   *
   * @returns A promise that resolves to the SDK's `AuthMetadataOptions`.
   * @throws {MCPAuthConfigError} if fetching the authorization server metadata fails.
   * @throws {MCPAuthAuthServerError} if the fetched metadata is invalid or does not satisfy the
   * MCP authorization specification.
   */
  async getAuthMetadataOptions(): Promise<AuthMetadataOptions> {
    const { resource, scopesSupported, resourceName, serviceDocumentationUrl } = this.config;
    const oauthMetadata = await this.#authServer.getMetadata();

    return {
      oauthMetadata,
      resourceServerUrl: new URL(resource),
      ...(scopesSupported && { scopesSupported }),
      ...(resourceName !== undefined && { resourceName }),
      ...(serviceDocumentationUrl !== undefined && {
        serviceDocumentationUrl: new URL(serviceDocumentationUrl),
      }),
    };
  }

  /**
   * Verifies a JWT access token issued by the trusted authorization server and returns the
   * extended auth info ({@link McpAuthInfo}).
   *
   * This method implements the MCP SDK's `OAuthTokenVerifier` interface, so the instance can be
   * passed directly as the `verifier` to the SDK's `requireBearerAuth` / `verifyBearerToken`
   * (or their framework adapters).
   *
   * The verification flow:
   *
   * 1. Decodes the token (without verifying) and rejects it unless its `iss` claim matches the
   *    trusted issuer — before any metadata or JWKS request is made.
   * 2. Resolves the authorization server metadata and JWK Set (both cached across calls).
   * 3. Verifies the token signature, `iss`, and `aud` (unless {@link MCPAuthConfig.audience} is
   *    `false`) claims, plus standard time claims, via `jose.jwtVerify`.
   * 4. Requires a non-empty `sub` claim (per RFC 9068) and maps the payload to
   *    {@link McpAuthInfo}: `clientId` from `client_id` (falling back to `azp`), `scopes` from
   *    `scope` (space-separated) or `scopes` (array), and `expiresAt` from `exp`.
   *
   * @param token The raw JWT access token.
   * @returns A promise that resolves to the verified auth info.
   * @throws {OAuthError} (from `@modelcontextprotocol/server`, with code `invalid_token`) if the
   * token is malformed, from an untrusted issuer, or fails verification. The SDK bearer-auth
   * helpers map this to a `401` response with a `WWW-Authenticate` challenge.
   * @throws {MCPAuthConfigError} if fetching the authorization server metadata fails; the SDK
   * bearer-auth helpers map non-`OAuthError` errors to a `500` response.
   * @throws {MCPAuthAuthServerError} if the authorization server metadata is invalid or has no
   * JWKS URI.
   */
  async verifyAccessToken(token: string): Promise<McpAuthInfo> {
    /*
     * Pre-check the issuer against the trusted authorization server before fetching any
     * metadata or JWKS, so this server only interacts with the expected authorization server.
     */
    const unverifiedIssuer = getUnverifiedJwtIssuer(token);
    const trustedIssuer = this.#authServer.issuer;

    if (unverifiedIssuer !== trustedIssuer) {
      throw new OAuthError(
        OAuthErrorCode.InvalidToken,
        `The token issuer (\`${unverifiedIssuer}\`) is not trusted. Expected \`${trustedIssuer}\`.`
      );
    }

    const [{ issuer }, jwks] = await Promise.all([
      this.#authServer.getMetadata(),
      this.#authServer.getJwks(),
    ]);

    const payload = await this.#verifyJwt(token, jwks, issuer);
    const { sub, exp } = payload;

    /*
     * RFC 9068 requires the `sub` claim in JWT access tokens, and `McpAuthInfo` guarantees a
     * `subject` to downstream consumers.
     */
    if (typeof sub !== 'string' || !sub) {
      throw new OAuthError(
        OAuthErrorCode.InvalidToken,
        'The JWT payload does not contain the `sub` field or it is malformed.'
      );
    }

    /*
     * Accept either `client_id` (RFC 9068) or `azp` for compatibility with providers that only
     * set the latter.
     * @see https://github.com/mcp-auth/js/issues/28
     */
    const clientId = payload.client_id ?? payload.azp;

    return {
      token,
      issuer,
      subject: sub,
      clientId: typeof clientId === 'string' ? clientId : '',
      scopes: getScopes(payload.scope) ?? getScopes(payload.scopes) ?? [],
      // The SDK bearer-auth helpers reject tokens without an expiration.
      expiresAt: exp,
      claims: payload,
    };
  }

  async #verifyJwt(token: string, jwks: JWTVerifyGetKey, issuer: string): Promise<JWTPayload> {
    const { audience = this.config.resource, jwtVerify: jwtVerifyOptions } = this.config;

    try {
      const { payload } = await jwtVerify(token, jwks, {
        ...jwtVerifyOptions,
        issuer,
        ...(audience === false ? {} : { audience }),
      });
      return payload;
    } catch (error) {
      throw new OAuthError(
        OAuthErrorCode.InvalidToken,
        error instanceof JOSEError
          ? `${error.code}: ${error.message}`
          : 'Failed to verify the access token.'
      );
    }
  }
}
