import { cond } from '@silverhand/essentials';

import { getIssuer } from '../types/auth-server.js';
import { type CamelCaseProtectedResourceMetadata } from '../types/oauth.js';
import { type ResourceServerConfig } from '../types/resource-server.js';

/**
 * Transforms protected resource metadata from MCPAuth config format to the standard OAuth 2.0 Protected Resource Metadata format.
 *
 * @remarks
 * The main transformation is converting the authorization servers from AuthServerConfig objects to their issuer URLs.
 * This is needed because the OAuth 2.0 Protected Resource Metadata specification expects authorization servers to be
 * represented as issuer URL strings, while MCP Auth internally uses `AuthServerConfig` objects to store the complete
 * authorization server metadata for token validation and issuer verification.
 *
 * Supports both resolved configs (with metadata) and discovery configs (with just issuer and type).
 *
 * @example
 * ```ts
 * const configMetadata = {
 *   resource: 'https://api.example.com',
 *   authorizationServers: [
 *     // Resolved config
 *     {
 *       type: 'oidc',
 *       metadata: {
 *         issuer: 'https://auth.example.com',
 *         // ... other auth server metadata
 *       }
 *     },
 *     // Discovery config
 *     {
 *       issuer: 'https://auth2.example.com',
 *       type: 'oidc'
 *     }
 *   ],
 *   scopesSupported: ['read', 'write']
 * };
 *
 * const standardMetadata = transpileResourceMetadata(configMetadata);
 * // Result:
 * // {
 * //   resource: 'https://api.example.com',
 * //   authorizationServers: ['https://auth.example.com', 'https://auth2.example.com'],
 * //   scopesSupported: ['read', 'write']
 * // }
 * ```
 *
 * @param metadata The protected resource metadata in MCPAuth config format
 * @returns The metadata transformed to standard OAuth 2.0 Protected Resource Metadata format
 */
export const transpileResourceMetadata = (
  metadata: ResourceServerConfig['metadata']
): CamelCaseProtectedResourceMetadata => {
  const { authorizationServers, ...rest } = metadata;

  return {
    ...rest,
    ...cond(
      authorizationServers?.length && {
        authorizationServers: authorizationServers.map((config) => getIssuer(config)),
      }
    ),
  };
};
