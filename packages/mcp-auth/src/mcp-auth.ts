import {
  getOAuthProtectedResourceMetadataUrl,
  OAuthError,
  OAuthErrorCode,
  type AuthMetadataOptions,
  type BearerAuthOptions,
  type OAuthTokenVerifier,
} from '@modelcontextprotocol/server';
import {
  decodeJwt,
  jwtVerify,
  type JWTPayload,
  type JWTVerifyGetKey,
  type JWTVerifyOptions,
} from 'jose';
import { JOSEError } from 'jose/errors';

import { type McpAuthInfo } from './auth-info.js';
import { AuthServerContext } from './auth-server-context.js';
import { MCPAuthConfigError } from './errors.js';
import { type AuthServerConfig } from './types.js';
import { parseAuthServerMetadata, validateResolvedMetadata } from './validate-auth-server.js';

/**
 * The RFC 9728 Protected Resource Metadata declaration of this MCP server: its identity
 * (`resource`), the authorization server it trusts, and the optional advertised fields.
 *
 * Everything in this declaration is published through the SDK's metadata helpers (via
 * {@link MCPAuth.getAuthMetadataOptions}), and the token verifier enforces what is declared:
 * the `aud` claim of access tokens must match `resource`, and the `iss` claim must match the
 * configured authorization server — what is advertised is what is enforced.
 */
export type ProtectedResourceMetadataConfig = {
  /**
   * The resource identifier of this MCP server (RFC 8707), e.g. `https://api.example.com/mcp`.
   *
   * It is published as the `resource` value of the Protected Resource Metadata document, used
   * as the expected `aud` (audience) claim of access tokens, and used to build
   * {@link MCPAuth.resourceMetadataUrl}.
   */
  resource: string;
  /**
   * The authorization server trusted by this MCP server, published as the single entry of
   * `authorization_servers` in the Protected Resource Metadata document. Either a discovery
   * config (`{ issuer, type }`, metadata fetched lazily on first use) or a resolved config with
   * metadata — hardcoded or pre-fetched via {@link fetchServerConfig}.
   *
   * @see {@link AuthServerConfig} for the two variants.
   */
  authorizationServer: AuthServerConfig;
  /**
   * The scopes this MCP server understands, advertised as `scopes_supported`.
   */
  scopesSupported?: string[];
  /**
   * A human-readable name for this MCP server, advertised as `resource_name`.
   */
  resourceName?: string;
  /**
   * A documentation URL for this MCP server, advertised as `resource_documentation`.
   */
  serviceDocumentationUrl?: string;
};

/**
 * Config for the {@link MCPAuth} class. One instance protects one resource and trusts one
 * authorization server.
 */
export type MCPAuthConfig = {
  /**
   * The Protected Resource Metadata declaration (RFC 9728) of this MCP server, published
   * through the SDK's metadata helpers and enforced by the token verifier.
   *
   * @see {@link ProtectedResourceMetadataConfig}
   */
  protectedResourceMetadata: ProtectedResourceMetadataConfig;
  /**
   * Per-call options passed to the underlying `jose.jwtVerify` function, e.g. `clockTolerance`
   * or `requiredClaims`. The `issuer` and `audience` options are derived from
   * {@link protectedResourceMetadata} and cannot be set here: the MCP authorization
   * specification requires access tokens to be bound to this server's `resource` identifier
   * (RFC 8707), and accepting unbound tokens would let a token issued for a different resource
   * of the same authorization server be replayed against this MCP server.
   *
   * @see {@link JWTVerifyOptions}
   */
  jwtVerifyOptions?: Omit<JWTVerifyOptions, 'issuer' | 'audience'>;
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
 * The `resource` identifier must be a hierarchical HTTP(S) URL — the SDK derives the RFC 9728
 * metadata URL from it, which throws a plain `TypeError` for non-hierarchical URIs such as
 * `urn:` — and must not contain a fragment component (forbidden by RFC 8707).
 */
const assertValidResource = (value: string) => {
  assertValidUrl(value, 'resource');
  const url = new URL(value);

  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new MCPAuthConfigError(
      'invalid_config',
      `The \`resource\` (\`${value}\`) must be an HTTP(S) URL.`
    );
  }

  if (url.hash) {
    throw new MCPAuthConfigError(
      'invalid_config',
      `The \`resource\` (\`${value}\`) must not contain a fragment component (RFC 8707).`
    );
  }
};

/**
 * The main class of the mcp-auth library, providing the two inputs the MCP TypeScript SDK asks
 * you to bring when protecting an MCP server — one method each:
 *
 * 1. **A token verifier** — the instance itself implements the SDK's `OAuthTokenVerifier`
 *    interface, and {@link getBearerAuthOptions} bundles it with the resource metadata URL
 *    into the SDK's `BearerAuthOptions`, ready to feed to `requireBearerAuth` (fetch-native or
 *    any of its framework adapters).
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
 *   protectedResourceMetadata: {
 *     resource: 'https://api.example.com/mcp',
 *     authorizationServer: { issuer: 'https://auth.example.com/oidc', type: 'oidc' },
 *     scopesSupported: ['read:notes'],
 *   },
 * });
 *
 * const createServer = () => {
 *   const server = new McpServer({ name: 'Notes', version: '1.0.0' });
 *   server.registerTool('whoami', { description: 'Get the current user' }, (ctx) => {
 *     const { subject, claims } = getAuthInfo(ctx);
 *     return { content: [{ type: 'text', text: JSON.stringify({ subject, claims }) }] };
 *   });
 *   return server;
 * };
 *
 * const handler = createMcpHandler(createServer);
 * const gate = requireBearerAuth(mcpAuth.getBearerAuthOptions({ requiredScopes: ['read:notes'] }));
 *
 * export default {
 *   async fetch(request: Request): Promise<Response> {
 *     // Serve the OAuth discovery documents; the path guard keeps the (lazily fetched)
 *     // metadata resolution off the request path of regular MCP traffic
 *     if (new URL(request.url).pathname.startsWith('/.well-known/')) {
 *       const metadataResponse = oauthMetadataResponse(request, await mcpAuth.getAuthMetadataOptions());
 *       if (metadataResponse) {
 *         return metadataResponse;
 *       }
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
 * import { createMcpExpressApp, mcpAuthMetadataRouter, requireBearerAuth } from '@modelcontextprotocol/express';
 * import { toNodeHandler } from '@modelcontextprotocol/node';
 * import { createMcpHandler } from '@modelcontextprotocol/server';
 * import { MCPAuth } from 'mcp-auth';
 *
 * const mcpAuth = new MCPAuth({
 *   protectedResourceMetadata: {
 *     resource: 'https://api.example.com/mcp',
 *     authorizationServer: { issuer: 'https://auth.example.com/oidc', type: 'oidc' },
 *     scopesSupported: ['read:notes'],
 *   },
 * });
 *
 * // Reuses `createServer` from the fetch-native example above
 * const mcpNodeHandler = toNodeHandler(createMcpHandler(createServer));
 *
 * const app = createMcpExpressApp();
 * app.use(mcpAuthMetadataRouter(await mcpAuth.getAuthMetadataOptions()));
 * app.all(
 *   '/mcp',
 *   requireBearerAuth(mcpAuth.getBearerAuthOptions({ requiredScopes: ['read:notes'] })),
 *   // `createMcpExpressApp` applies `express.json()`, which drains the request stream, so the
 *   // parsed body is passed along explicitly
 *   async (request, response) => mcpNodeHandler(request, response, request.body)
 * );
 * app.listen(3000);
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
    const { resource, authorizationServer, serviceDocumentationUrl } =
      config.protectedResourceMetadata;

    if (!resource) {
      throw new MCPAuthConfigError('invalid_config', 'A `resource` identifier is required.');
    }
    assertValidResource(resource);

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

    this.#authServer = new AuthServerContext(authorizationServer);
  }

  /**
   * The RFC 9728 Protected Resource Metadata URL for the configured
   * {@link ProtectedResourceMetadataConfig.resource}, built with the MCP SDK's
   * `getOAuthProtectedResourceMetadataUrl`.
   *
   * Pass it as the `resourceMetadataUrl` option of the SDK's `requireBearerAuth` so the
   * `WWW-Authenticate` challenge on `401` responses points clients at the metadata document.
   *
   * @example
   * ```ts
   * const mcpAuth = new MCPAuth({
   *   protectedResourceMetadata: { resource: 'https://api.example.com/mcp', ... },
   * });
   * mcpAuth.resourceMetadataUrl
   * // → 'https://api.example.com/.well-known/oauth-protected-resource/mcp'
   * ```
   */
  get resourceMetadataUrl(): string {
    return getOAuthProtectedResourceMetadataUrl(
      new URL(this.config.protectedResourceMetadata.resource)
    );
  }

  /**
   * Builds the MCP SDK's `BearerAuthOptions` from this instance: the instance itself as the
   * `verifier` and {@link resourceMetadataUrl} for the `WWW-Authenticate` challenge, plus the
   * per-endpoint `requiredScopes` you pass in.
   *
   * Feed the result to `requireBearerAuth` — the fetch-native one from
   * `@modelcontextprotocol/server` and the Express middleware from
   * `@modelcontextprotocol/express` accept the same options type. Endpoints with different
   * scope requirements call this method once each.
   *
   * @example
   * ```ts
   * // Fetch-native (Cloudflare Workers, Deno, Bun, Node.js)
   * const gate = requireBearerAuth(mcpAuth.getBearerAuthOptions({ requiredScopes: ['read:notes'] }));
   *
   * // Express
   * app.post('/mcp', requireBearerAuth(mcpAuth.getBearerAuthOptions({ requiredScopes: ['read:notes'] })), ...);
   * ```
   *
   * @param options Per-endpoint bearer-auth requirements.
   * @returns The SDK's `BearerAuthOptions`, ready to pass to `requireBearerAuth`.
   */
  getBearerAuthOptions(options?: Pick<BearerAuthOptions, 'requiredScopes'>): BearerAuthOptions {
    return {
      verifier: this,
      resourceMetadataUrl: this.resourceMetadataUrl,
      ...options,
    };
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
    const { resource, scopesSupported, resourceName, serviceDocumentationUrl } =
      this.config.protectedResourceMetadata;
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
   * 3. Verifies the token signature and the `iss` and `aud` claims (the `aud` claim must match
   *    the {@link ProtectedResourceMetadataConfig.resource} identifier, per the RFC 8707
   *    audience binding the MCP authorization specification requires), plus standard time
   *    claims, via `jose.jwtVerify`.
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
    const { protectedResourceMetadata, jwtVerifyOptions } = this.config;

    try {
      /*
       * The `issuer` and `audience` options are set after the spread so they can never be
       * overridden: the MCP authorization specification requires the token audience to be
       * this server's `resource` identifier (RFC 8707).
       */
      const { payload } = await jwtVerify(token, jwks, {
        ...jwtVerifyOptions,
        issuer,
        audience: protectedResourceMetadata.resource,
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
