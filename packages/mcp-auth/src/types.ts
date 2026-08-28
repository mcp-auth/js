import { type OAuthMetadata } from '@modelcontextprotocol/server';

/**
 * The type of the authorization server. It determines which discovery convention is used to
 * locate the server metadata:
 *
 * - `'oidc'`: OpenID Connect Discovery (`<issuer>/.well-known/openid-configuration`)
 * - `'oauth'`: OAuth 2.0 Authorization Server Metadata (RFC 8414 path insertion,
 *   `<origin>/.well-known/oauth-authorization-server<issuer-path>`)
 */
export type AuthServerType = 'oauth' | 'oidc';

/**
 * Authorization server metadata in wire format (snake_case), as fetched from the server's
 * discovery endpoint or provided directly in the configuration.
 *
 * This is the MCP SDK's RFC 8414 `OAuthMetadata` type, extended with the `jwks_uri` field that
 * mcp-auth requires for JWT verification. The metadata is passed verbatim (no key-casing
 * transformation) to the SDK's metadata helpers such as `oauthMetadataResponse` and
 * `mcpAuthMetadataRouter`.
 *
 * Note: mcp-auth validates the fields it consumes (`issuer`, `authorization_endpoint`,
 * `token_endpoint`, `response_types_supported`, `jwks_uri`, `grant_types_supported`,
 * `code_challenge_methods_supported`, `registration_endpoint`); other fields are passed through
 * as-is.
 *
 * @see [OAuth 2.0 Authorization Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414)
 * @see [OpenID Connect Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html)
 */
export type AuthServerMetadata = OAuthMetadata & {
  /**
   * URL of the authorization server's JWK Set document, used to verify JWT access token
   * signatures. Required by OpenID Connect Discovery; optional in RFC 8414 but required by
   * mcp-auth when verifying tokens.
   */
  jwks_uri?: string;
};

/**
 * Resolved configuration for the remote authorization server with metadata.
 *
 * Use this when the metadata is already available — either provided directly or fetched
 * beforehand via {@link fetchServerConfig}. The metadata is validated in the `MCPAuth`
 * constructor so misconfigurations fail fast.
 */
export type ResolvedAuthServerConfig = {
  /**
   * The metadata of the authorization server in wire format (snake_case).
   *
   * @see {@link AuthServerMetadata} for the type definition.
   */
  metadata: AuthServerMetadata;
  /**
   * The type of the authorization server.
   *
   * @see {@link AuthServerType} for the possible values.
   */
  type: AuthServerType;
};

/**
 * Discovery configuration for the remote authorization server.
 *
 * Use this when you want the metadata to be fetched on-demand when first needed. This is
 * required for edge runtimes like Cloudflare Workers where network requests are not allowed
 * during module initialization, and it avoids a startup fetch elsewhere.
 *
 * @example
 * ```ts
 * const mcpAuth = new MCPAuth({
 *   resource: 'https://api.example.com/mcp',
 *   authorizationServer: { issuer: 'https://auth.example.com/oidc', type: 'oidc' },
 * });
 * ```
 */
export type AuthServerDiscoveryConfig = {
  /**
   * The issuer URL of the authorization server. The metadata will be fetched from the
   * well-known endpoint derived from this issuer according to the server type.
   */
  issuer: string;
  /**
   * The type of the authorization server.
   *
   * @see {@link AuthServerType} for the possible values.
   */
  type: AuthServerType;
};

/**
 * Configuration for the remote authorization server trusted by the MCP server.
 *
 * Can be either:
 *
 * - **Discovery**: contains `issuer` and `type` — metadata is fetched on-demand and cached
 * - **Resolved**: contains `metadata` — no network request needed
 */
export type AuthServerConfig = ResolvedAuthServerConfig | AuthServerDiscoveryConfig;

/**
 * Get the issuer identifier from an auth server config.
 *
 * - Resolved config: extracts from `metadata.issuer`
 * - Discovery config: returns `issuer` directly
 */
export const getIssuer = (config: AuthServerConfig): string =>
  'metadata' in config ? config.metadata.issuer : config.issuer;
