import { type Optional } from '@silverhand/essentials';
import type { RequestHandler, Router } from 'express';
import { type RemoteJWKSetOptions, type JWTVerifyOptions } from 'jose';

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

type AuthServerModeConfig = {
  /**
   * @deprecated Use `ResourceServerModeConfig` config instead.
   */
  server: AuthServerConfig;
};

type ResourceServerModeConfig = {
  protectedResource: ResourceServerConfig | ResourceServerConfig[];
};

/**
 * Config for the {@link MCPAuth} class.
 */
export type MCPAuthConfig = AuthServerModeConfig | ResourceServerModeConfig;

export type VerifyAccessTokenMode = 'jwt';

/**
 * Configuration for the Bearer auth handler when using JWT verification.
 */
export type BearerAuthJwtConfig = {
  /**
   * Options to pass to the `jose` library's `jwtVerify` function.
   *
   * The issuer option is hardcoded to the authorization server’s issuer.
   *
   * @see {@link JWTVerifyOptions} for the type definition of the options.
   */
  jwtVerify?: JWTVerifyOptions;
  /**
   * Options to pass to the `jose` library's `createRemoteJWKSet` function.
   *
   * @see {@link RemoteJWKSetOptions} for the type definition of the options.
   */
  remoteJwkSet?: RemoteJWKSetOptions;
};

/**
 * The main class for the mcp-auth library, which provides methods to create routers and useful
 * handlers for authentication and authorization in MCP servers.
 *
 * @see {@link https://mcp-auth.dev | MCP Auth} for more information about the library and its
 * usage.
 *
 * @example
 * An example integrating with a remote OIDC provider:
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
 * // Mount the router to handle OAuth 2.0 Authorization Server Metadata
 * app.use(mcpAuth.delegatedRouter());
 *
 * // Use the Bearer auth handler the MCP route
 * app.get(
 *   '/mcp',
 *   mcpAuth.bearerAuth('jwt', { requiredScopes: ['read', 'write'] }),
 *   (req, res) => {
 *     console.log('Auth info:', req.auth);
 *     // Handle the MCP request here
 *   },
 * );
 *
 * // Use the auth info in the MCP callback
 * server.tool(
 *   'add',
 *   { a: z.number(), b: z.number() },
 *   async ({ a, b }, { authInfo }) => {
 *     console.log('Auth Info:', authInfo);
 *    // ...
 *   },
 * );
 * ```
 */
export class MCPAuth {
  /** @deprecated */
  private readonly authServerTokenVerifier: Optional<TokenVerifier> = undefined;
  private readonly resourceServerTokenVerifiers: Optional<Map<string, TokenVerifier>> = undefined;

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

    if ('server' in config) {
      console.warn(
        'The `server` config is deprecated. Please migrate to using only `protectedResource`.'
      );

      this.validateAuthServerConfig(config);

      this.authServerTokenVerifier = new TokenVerifier([config.server]);

      return;
    }

    if ('protectedResource' in config) {
      this.validateResourceServerConfig(config);

      this.resourceServerTokenVerifiers = new Map();

      const resourceServerConfigs = Array.isArray(config.protectedResource)
        ? config.protectedResource
        : [config.protectedResource];

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
   * @deprecated Use {@link protectedResourceMetadataRouter} instead.
   *
   * Creates a delegated router that serves the OAuth 2.0 Authorization Server Metadata endpoint
   * (`/.well-known/oauth-authorization-server`) with the metadata provided to the instance.
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
    }: Omit<BearerAuthConfig, 'verifyAccessToken' | 'issuer'> & BearerAuthJwtConfig = {}
  ): RequestHandler {
    if ('protectedResource' in this.config && !config.resource) {
      throw new MCPAuthAuthServerError('invalid_server_config', {
        cause:
          'A `resource` must be specified in the `bearerAuth` configuration when using a `protectedResource` configuration.',
      });
    }

    const tokenVerifier = this.getTokenVerifier(config.resource);

    if (!tokenVerifier) {
      if ('protectedResource' in this.config) {
        throw new MCPAuthAuthServerError('invalid_server_config', {
          cause: `No token verifier found for the specified resource: \`${config.resource}\`. \\nPlease ensure that this resource is correctly configured in the \`protectedResource\` array in the MCPAuth constructor.`,
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

  private getTokenVerifier(resource?: string): Optional<TokenVerifier> {
    if ('server' in this.config) {
      return this.authServerTokenVerifier;
    }

    if (!resource) {
      throw new MCPAuthAuthServerError('invalid_server_config', {
        cause:
          'Missing `resource` to identify the protected resource metadata when using a `protectedResource` configuration.',
      });
    }

    return this.resourceServerTokenVerifiers?.get(resource);
  }

  private validateAuthServerConfig(config: AuthServerModeConfig) {
    const { server } = config;
    this.validateAuthServer(server);
  }

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
