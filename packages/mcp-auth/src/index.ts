import { type Optional } from '@silverhand/essentials';
import type { RequestHandler, Router } from 'express';

import { TokenVerifier, type VerifyJwtConfig } from './auth/token-verifier.js';
import { MCPAuthAuthServerError } from './errors.js';
import {
  handleBearerAuth,
  type VerifyAccessTokenFunction,
  type BearerAuthConfig,
} from './handlers/handle-bearer-auth.js';
import { createDelegatedRouter } from './routers/create-delegated-router.js';
import { createResourceMetadataRouter } from './routers/create-resource-metadata-router.js';
import { type AuthServerConfig } from './types/auth-server.js';
import { type ResourceServerConfig } from './types/resource-server.js';
import { transpileResourceMetadata } from './utils/transpile-resource-metadata.js';
import { validateServerConfig } from './utils/validate-server-config.js';

export * from './types/oauth.js';
export * from './types/auth-server.js';
export * from './errors.js';
export * from './handlers/handle-bearer-auth.js';
export * from './utils/fetch-server-config.js';
export * from './utils/validate-server-config.js';
export * from './utils/create-verify-jwt.js';

/**
 * @internal
 * Configuration for the legacy, MCP server as authorization server mode.
 */
type AuthServerModeConfig = {
  /**
   * The single authorization server configuration.
   * @deprecated Use `protectedResource` config instead.
   */
  server: AuthServerConfig;
};

/**
 * @internal
 * Configuration for the modern, MCP server as resource server mode.
 */
type ResourceServerModeConfig = {
  /**
   * A single resource server configuration or an array of them.
   */
  protectedResource: ResourceServerConfig | ResourceServerConfig[];
};

/**
 * Config for the {@link MCPAuth} class, supporting either a single legacy `authorization server`
 * or the `resource server` configuration.
 */
export type MCPAuthConfig = AuthServerModeConfig | ResourceServerModeConfig;

/**
 * The built-in verification modes supported by `bearerAuth`.
 */
export type VerifyAccessTokenMode = 'jwt';

/**
 * The main class for the mcp-auth library. It acts as a factory and registry for creating
 * authentication policies for your protected resources.
 *
 * It is initialized with your server configurations and provides a `bearerAuth` method
 * to generate Express middleware for token-based authentication.
 *
 * @example
 * ### Modern Usage with `protectedResource`
 *
 * This is the recommended approach for new applications.
 *
 * ```ts
 * import express from 'express';
 * import { MCPAuth, fetchServerConfig } from 'mcp-auth';
 *
 * const app = express();
 *
 * const resourceIdentifier = 'https://api.example.com/notes';
 * const authServerConfig = await fetchServerConfig('https://auth.logto.io/oidc', { type: 'oidc' });
 *
 * const mcpAuth = new MCPAuth({
 *   protectedResource: {
 *     metadata: {
 *       resource: resourceIdentifier,
 *       authorizationServers: [authServerConfig],
 *       scopesSupported: ['read:notes', 'write:notes'],
 *     },
 *   },
 * });
 *
 * // Mount the router to handle Protected Resource Metadata
 * app.use(mcpAuth.protectedResourceMetadataRouter());
 *
 * // Protect an API endpoint for the configured resource
 * app.get(
 *   '/notes',
 *   mcpAuth.bearerAuth('jwt', {
 *     resource: resourceIdentifier, // Specify which resource this endpoint belongs to
 *     audience: resourceIdentifier, // Optionally, validate the 'aud' claim
 *     requiredScopes: ['read:notes'],
 *   }),
 *   (req, res) => {
 *     console.log('Auth info:', req.auth);
 *     res.json({ notes: [] });
 *   },
 * );
 * ```
 *
 * ### Legacy Usage with `server` (Deprecated)
 *
 * This approach is supported for backward compatibility.
 *
 * ```ts
 * import express from 'express';
 * import { MCPAuth, fetchServerConfig } from 'mcp-auth';
 *
 * const app = express();
 * const mcpAuth = new MCPAuth({
 *   server: await fetchServerConfig(
 *     'https://auth.logto.io/oidc',
 *     { type: 'oidc' }
 *   ),
 * });
 *
 * // Mount the router to handle legacy Authorization Server Metadata
 * app.use(mcpAuth.delegatedRouter());
 *
 * // Protect an endpoint using the default policy
 * app.get(
 *   '/mcp',
 *   mcpAuth.bearerAuth('jwt', { requiredScopes: ['read', 'write'] }),
 *   (req, res) => {
 *     console.log('Auth info:', req.auth);
 *     // Handle the MCP request here
 *   },
 * );
 * ```
 */
export class MCPAuth {
  /** The `TokenVerifier` for the legacy `server` configuration. */
  private readonly authServerTokenVerifier: Optional<TokenVerifier> = undefined;
  /** A map of `TokenVerifier` instances for each configured resource server, keyed by resource identifier. */
  private readonly resourceServerTokenVerifiers: Optional<Map<string, TokenVerifier>> = undefined;

  /**
   * Creates an instance of MCPAuth.
   * It validates the entire configuration upfront to fail fast on errors.
   * @param config The authentication configuration.
   */
  constructor(public readonly config: MCPAuthConfig) {
    if (!('server' in config || 'protectedResource' in config)) {
      throw new MCPAuthAuthServerError('invalid_server_config', {
        cause: 'No authorization server or protected resource metadata is provided.',
      });
    }

    if ('server' in config && 'protectedResource' in config) {
      throw new MCPAuthAuthServerError('invalid_server_config', {
        cause:
          'Both `server` and `protectedResource` cannot be provided at the same time.\nPlease migrate to using only `protectedResource`.',
      });
    }

    // --- Legacy `server` mode initialization ---
    if ('server' in config) {
      console.warn(
        'The `server` config is deprecated. Please migrate to using only `protectedResource`.'
      );

      this.validateAuthServerConfig(config);
      this.authServerTokenVerifier = new TokenVerifier([config.server]);
      return;
    }

    // --- `protectedResource` mode initialization ---
    if ('protectedResource' in config) {
      this.validateResourceServerConfig(config);
      this.resourceServerTokenVerifiers = new Map();

      const resourceServerConfigs = Array.isArray(config.protectedResource)
        ? config.protectedResource
        : [config.protectedResource];

      // Create a dedicated TokenVerifier for each unique resource server configuration.
      for (const resourceServerConfig of resourceServerConfigs) {
        const {
          metadata: { resource, authorizationServers },
        } = resourceServerConfig;

        this.resourceServerTokenVerifiers.set(
          resource,
          new TokenVerifier(authorizationServers ?? [])
        );
      }
    }
  }

  /**
   * Creates a delegated router for serving legacy OAuth 2.0 Authorization Server Metadata endpoint
   * (`/.well-known/oauth-authorization-server`) with the metadata provided to the instance.
   *
   * @deprecated Use {@link protectedResourceMetadataRouter} instead.
   *
   * @example
   * ```ts
   * import express from 'express';
   * import { MCPAuth } from 'mcp-auth';
   *
   * const app = express();
   * const mcpAuth: MCPAuth; // Assume this is initialized
   * app.use(mcpAuth.delegatedRouter());
   * ```
   *
   * @returns A router that serves the OAuth 2.0 Authorization Server Metadata endpoint with the
   * metadata provided to the instance.
   */
  delegatedRouter(): Router {
    if (!('server' in this.config)) {
      throw new MCPAuthAuthServerError('invalid_server_config', {
        cause: 'No authorization server configuration is provided.',
      });
    }

    return createDelegatedRouter(this.config.server.metadata);
  }

  /**
   * Creates a router that serves the OAuth 2.0 Protected Resource Metadata endpoint
   * for all configured resources.
   *
   * This router automatically creates the correct `.well-known` endpoints for each
   * resource identifier provided in your configuration.
   *
   * @example
   * ```ts
   * import express from 'express';
   * import { MCPAuth } from 'mcp-auth';
   *
   * // Assuming mcpAuth is initialized with one or more `protectedResource` configs
   * const mcpAuth: MCPAuth;
   * const app = express();
   *
   * // This will serve metadata at `/.well-known/oauth-protected-resource/...`
   * // based on your resource identifiers.
   * app.use(mcpAuth.protectedResourceMetadataRouter());
   * ```
   */
  protectedResourceMetadataRouter(): Router {
    if (!('protectedResource' in this.config)) {
      throw new MCPAuthAuthServerError('invalid_server_config', {
        cause: 'No resource server configuration is provided.',
      });
    }

    const { protectedResource } = this.config;
    const configs = Array.isArray(protectedResource) ? protectedResource : [protectedResource];

    return createResourceMetadataRouter(
      configs.map((config) => transpileResourceMetadata(config.metadata))
    );
  }

  /**
   * Creates a Bearer auth handler (Express middleware) that verifies the access token in the
   * `Authorization` header of the request.
   *
   * @see {@link handleBearerAuth} for the implementation details and the extended types of the
   * `req.auth` (`AuthInfo`) object.
   * @returns An Express middleware function that verifies the access token and adds the
   * verification result to the request object (`req.auth`).
   */
  bearerAuth(
    /**
     * A function that verifies the access token. It should accept the
     * access token as a string and return a promise (or a value) that resolves to the
     * verification result.
     *
     * @see {@link VerifyAccessTokenFunction} for the type definition of the
     * `verifyAccessToken` function.
     */
    verifyAccessToken: VerifyAccessTokenFunction,
    /**
     * Optional configuration for the Bearer auth handler.
     *
     * @see {@link BearerAuthConfig} for the available configuration options (excluding
     * `verifyAccessToken` and `issuer`).
     */
    config?: Omit<BearerAuthConfig, 'verifyAccessToken' | 'issuer'>
  ): RequestHandler;
  /**
   * Creates a Bearer auth handler (Express middleware) that verifies the access token in the
   * `Authorization` header of the request using a predefined mode of verification.
   *
   * In the `'jwt'` mode, the handler will create a JWT verification function using the JWK Set
   * from the authorization server's JWKS URI.
   *
   * @see {@link handleBearerAuth} for the implementation details and the extended types of the
   * `req.auth` (`AuthInfo`) object.
   * @returns An Express middleware function that verifies the access token and adds the
   * verification result to the request object (`req.auth`).
   * @throws {MCPAuthAuthServerError} if the JWKS URI is not provided in the server metadata when
   * using the `'jwt'` mode.
   */
  bearerAuth(
    /**
     * The mode of verification for the access token. Currently, only 'jwt' is supported.
     *
     * @see {@link VerifyAccessTokenMode} for the available modes.
     */
    mode: VerifyAccessTokenMode,
    /**
     * Optional configuration for the Bearer auth handler, including JWT verification options and
     * remote JWK set options.
     *
     * @see {@link VerifyJwtConfig} for the available configuration options for JWT
     * verification.
     * @see {@link BearerAuthConfig} for the available configuration options (excluding
     * `verifyAccessToken` and `issuer`).
     */
    config?: Omit<BearerAuthConfig, 'verifyAccessToken' | 'issuer'> & VerifyJwtConfig
  ): RequestHandler;
  bearerAuth(
    modeOrVerify: VerifyAccessTokenMode | VerifyAccessTokenFunction,
    {
      jwtVerify,
      remoteJwkSet,
      ...config
    }: Omit<BearerAuthConfig, 'verifyAccessToken' | 'issuer'> & VerifyJwtConfig = {}
  ): RequestHandler {
    // The `resource` property in the config is crucial for selecting the correct TokenVerifier
    // in `protectedResource` mode. This check ensures it's not forgotten.
    if ('protectedResource' in this.config && !config.resource) {
      throw new MCPAuthAuthServerError('invalid_server_config', {
        cause:
          'A `resource` must be specified in the `bearerAuth` configuration when using a `protectedResource` configuration.',
      });
    }

    // Resolve the correct policy object (TokenVerifier) based on the configuration.
    const tokenVerifier = this.getTokenVerifier(config.resource);

    if (!tokenVerifier) {
      if ('protectedResource' in this.config) {
        throw new MCPAuthAuthServerError('invalid_server_config', {
          cause: `No token verifier found for the specified resource: \`${config.resource}\`. Please ensure that this resource is correctly configured in the \`protectedResource\` array in the MCPAuth constructor.`,
        });
      }

      throw new MCPAuthAuthServerError('invalid_server_config', {
        cause: 'No authorization server or resource server configuration is provided.',
      });
    }

    const getVerifyFunction = () => {
      if (typeof modeOrVerify === 'function') {
        return modeOrVerify;
      }

      // If a mode is provided, create the verification function from the TokenVerifier.
      switch (modeOrVerify) {
        case 'jwt': {
          return tokenVerifier.createVerifyJwtFunction({ jwtVerify, remoteJwkSet });
        }
      }
    };

    return handleBearerAuth({
      verifyAccessToken: getVerifyFunction(),
      issuer: tokenVerifier.validateJwtIssuer,
      ...config,
    });
  }

  /**
   * A private helper to resolve the correct `TokenVerifier` based on the current
   * configuration mode and the provided resource identifier.
   */
  private getTokenVerifier(resource?: string): Optional<TokenVerifier> {
    // In legacy `server` mode, always use the single default verifier.
    if ('server' in this.config) {
      return this.authServerTokenVerifier;
    }

    /**
     * In `protectedResource` mode, a resource identifier is required to look up
     * the correct verifier from the map.
     */
    if (!resource) {
      throw new MCPAuthAuthServerError('invalid_server_config', {
        cause:
          'Missing `resource` to identify the protected resource metadata when using a `protectedResource` configuration.',
      });
    }

    return this.resourceServerTokenVerifiers?.get(resource);
  }

  /**
   * Validates the configuration for the legacy `server` mode.
   */
  private validateAuthServerConfig(config: AuthServerModeConfig) {
    const { server } = config;
    this.validateAuthServer(server);
  }

  /**
   * Validates the configuration for the modern `protectedResource` mode,
   * checking for duplicate resources and related authorization servers.
   */
  private validateResourceServerConfig(config: ResourceServerModeConfig) {
    const { protectedResource } = config;

    const resourceConfigs = Array.isArray(protectedResource)
      ? protectedResource
      : [protectedResource];

    const uniqueResource = new Map<string, boolean>();

    for (const resourceConfig of resourceConfigs) {
      const {
        metadata: { resource, authorizationServers },
      } = resourceConfig;

      if (uniqueResource.has(resource)) {
        throw new MCPAuthAuthServerError('invalid_server_config', {
          cause: `The resource metadata (\`${resource}\`) is duplicated.`,
        });
      }

      uniqueResource.set(resource, true);

      const uniqueAuthServers = new Map<string, boolean>();

      for (const authServer of authorizationServers ?? []) {
        const { issuer } = authServer.metadata;
        if (uniqueAuthServers.has(issuer)) {
          throw new MCPAuthAuthServerError('invalid_server_config', {
            cause: `The authorization server (\`${issuer}\`) for resource \`${resource}\` is duplicated.`,
          });
        }
        uniqueAuthServers.set(issuer, true);

        this.validateAuthServer(authServer);
      }
    }
  }

  /**
   * Validates a single `AuthServerConfig` object.
   */
  private validateAuthServer(authServer: AuthServerConfig) {
    const result = validateServerConfig(authServer);

    if (!result.isValid) {
      throw new MCPAuthAuthServerError('invalid_server_config', {
        ...result,
      });
    }

    if (result.warnings.length > 0) {
      console.warn(
        `The authorization server (issuer: \`${authServer.metadata.issuer}\`) configuration has warnings:\n\n  - ${result.warnings.map(({ description }) => description).join('\n  - ')}\n`
      );
    }
  }
}
