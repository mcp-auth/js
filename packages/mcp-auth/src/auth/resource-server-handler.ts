import { type Router } from 'express';

import { MCPAuthAuthServerError } from '../errors.js';
import { createResourceMetadataRouter } from '../routers/create-resource-metadata-router.js';
import { type ResourceServerConfig } from '../types/resource-server.js';
import { transpileResourceMetadata } from '../utils/transpile-resource-metadata.js';
import { validateAuthServer } from '../utils/validate-auth-server.js';

import { MCPAuthHandler } from './mcp-auth-handler.js';
import { TokenVerifier } from './token-verifier.js';

/**
 * Configuration for the MCP server as resource server mode.
 */
export type ResourceServerModeConfig = {
  /**
   * A single resource server configuration or an array of them.
   */
  protectedResources: ResourceServerConfig | ResourceServerConfig[];
};
/**
 * Handles the authentication logic for the MCP server as resource server mode.
 */
export class ResourceServerHandler extends MCPAuthHandler {
  /** A map of `TokenVerifier` instances for each configured resource server, keyed by resource identifier. */
  private readonly tokenVerifiers: Map<string, TokenVerifier>;

  constructor(private readonly config: ResourceServerModeConfig) {
    super();
    this.#validateConfig(this.resourcesConfigs);

    this.tokenVerifiers = new Map();
    for (const resourceConfig of this.resourcesConfigs) {
      const {
        metadata: { resource, authorizationServers },
      } = resourceConfig;
      this.tokenVerifiers.set(resource, new TokenVerifier(authorizationServers ?? []));
    }
  }

  createMetadataRouter(): Router {
    return createResourceMetadataRouter(
      this.resourcesConfigs.map((config) => transpileResourceMetadata(config.metadata))
    );
  }

  getTokenVerifier(options: { resource?: string }): TokenVerifier {
    const { resource } = options;

    if (!resource) {
      throw new MCPAuthAuthServerError('invalid_server_config', {
        cause:
          'A `resource` must be specified in the `bearerAuth` configuration when using a `protectedResources` configuration.',
      });
    }

    const verifier = this.tokenVerifiers.get(resource);

    if (!verifier) {
      throw new MCPAuthAuthServerError('invalid_server_config', {
        cause: `No token verifier found for the specified resource: \`${resource}\`. Please ensure that this resource is correctly configured in the \`protectedResources\` array in the MCPAuth constructor.`,
      });
    }

    return verifier;
  }

  #validateConfig(resourceConfigs: ResourceServerConfig[]) {
    const uniqueResource = new Set<string>();

    for (const {
      metadata: { resource, authorizationServers },
    } of resourceConfigs) {
      if (uniqueResource.has(resource)) {
        throw new MCPAuthAuthServerError('invalid_server_config', {
          cause: `The resource metadata (\`${resource}\`) is duplicated.`,
        });
      }
      uniqueResource.add(resource);

      const uniqueAuthServers = new Set<string>();
      for (const authServer of authorizationServers ?? []) {
        const { issuer } = authServer.metadata;
        if (uniqueAuthServers.has(issuer)) {
          throw new MCPAuthAuthServerError('invalid_server_config', {
            cause: `The authorization server (\`${issuer}\`) for resource \`${resource}\` is duplicated.`,
          });
        }
        uniqueAuthServers.add(issuer);
        validateAuthServer(authServer);
      }
    }
  }

  private get resourcesConfigs() {
    return Array.isArray(this.config.protectedResources)
      ? this.config.protectedResources
      : [this.config.protectedResources];
  }
}
