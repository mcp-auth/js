import { type CamelCaseAuthorizationServerMetadata } from './oauth.js';

/**
 * The type of the authorization server. This information should be provided by the server
 * configuration and indicates whether the server is an OAuth 2.0 or OpenID Connect (OIDC)
 * authorization server.
 */
export type AuthServerType = 'oauth' | 'oidc';

/**
 * Resolved configuration for the remote authorization server with metadata.
 *
 * Use this when the metadata is already available, either hardcoded or fetched beforehand
 * via `fetchServerConfig()`.
 */
export type ResolvedAuthServerConfig = {
  /**
   * The metadata of the authorization server, which should conform to the MCP specification
   * (based on OAuth 2.0 Authorization Server Metadata).
   *
   * This metadata is typically fetched from the server's well-known endpoint (OAuth 2.0
   * Authorization Server Metadata or OpenID Connect Discovery); it can also be provided
   * directly in the configuration if the server does not support such endpoints.
   *
   * **Note:** The metadata should be in camelCase format as per preferred by the mcp-auth
   * library.
   *
   * @see [OAuth 2.0 Authorization Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414)
   * @see [OpenID Connect Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html)
   */
  metadata: CamelCaseAuthorizationServerMetadata;
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
 * Use this when you want the metadata to be fetched on-demand via discovery when first needed.
 * This is useful for edge runtimes like Cloudflare Workers where top-level async fetch
 * is not allowed.
 *
 * @example
 * ```typescript
 * const mcpAuth = new MCPAuth({
 *   protectedResources: {
 *     metadata: {
 *       resource: 'https://api.example.com',
 *       authorizationServers: [
 *         { issuer: 'https://auth.logto.io/oidc', type: 'oidc' }
 *       ],
 *       scopesSupported: ['read', 'write'],
 *     },
 *   },
 * });
 * ```
 */
export type AuthServerDiscoveryConfig = {
  /**
   * The issuer URL of the authorization server. The metadata will be fetched from the
   * well-known endpoint derived from this issuer.
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
 * Configuration for the remote authorization server integrated with the MCP server.
 *
 * Can be either:
 * - **Resolved**: Contains `metadata` - no network request needed
 * - **Discovery**: Contains only `issuer` and `type` - metadata fetched on-demand via discovery
 */
export type AuthServerConfig = ResolvedAuthServerConfig | AuthServerDiscoveryConfig;

/**
 * Get the issuer URL from an auth server config.
 *
 * - Resolved config: extracts from `metadata.issuer`
 * - Discovery config: returns `issuer` directly
 */
export const getIssuer = (config: AuthServerConfig): string =>
  'metadata' in config ? config.metadata.issuer : config.issuer;
