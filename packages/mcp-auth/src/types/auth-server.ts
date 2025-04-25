import { type CamelCaseAuthorizationServerMetadata } from './oauth.js';

/**
 * The type of the authorization server. This information should be provided by the server
 * configuration and indicates whether the server is an OAuth 2.0 or OpenID Connect (OIDC)
 * authorization server.
 */
export type AuthServerType = 'oauth' | 'oidc';

/**
 * Configuration for the remote authorization server integrated with the MCP server.
 */
export type AuthServerConfig = {
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
