/**
 * The MCP TypeScript SDK asks you to bring two things when protecting an MCP server: a token
 * verifier and your auth metadata. mcp-auth gives you both, for any OAuth 2.0 / OpenID Connect
 * provider:
 *
 * - {@link MCPAuth} implements the SDK's `OAuthTokenVerifier` and builds the SDK's
 *   `AuthMetadataOptions` from your provider's discovery metadata.
 * - {@link getAuthInfo} reads the verified {@link McpAuthInfo} back out of a request handler
 *   context.
 * - {@link fetchServerConfig} fetches and validates a provider's discovery metadata standalone.
 *
 * @see {@link MCPAuth} for complete usage examples.
 */

export {
  getAuthInfo,
  isMcpAuthInfo,
  type GetAuthInfoOptions,
  type McpAuthInfo,
} from './auth-info.js';
export * from './errors.js';
export {
  fetchServerConfig,
  fetchServerConfigByWellKnownUrl,
  serverMetadataPaths,
  type ServerMetadataConfig,
} from './fetch-server-config.js';
export { MCPAuth, type MCPAuthConfig } from './mcp-auth.js';
export {
  type AuthServerConfig,
  type AuthServerDiscoveryConfig,
  type AuthServerMetadata,
  type AuthServerType,
  type ResolvedAuthServerConfig,
} from './types.js';
