import { cond } from '@silverhand/essentials';
import type { RequestHandler, Router } from 'express';
import {
  createRemoteJWKSet,
  type RemoteJWKSetOptions,
  type JWTVerifyOptions,
  decodeJwt,
} from 'jose';

import { MCPAuthAuthServerError, MCPAuthBearerAuthError } from './errors.js';
import {
  handleBearerAuth,
  type VerifyAccessTokenFunction,
  type BearerAuthConfig,
  type ValidateIssuerFunction,
} from './handlers/handle-bearer-auth.js';
import {
  createDelegatedRouter,
  createProtectedResourceMetadataRouter,
} from './routers/create-delegated-router.js';
import { type AuthServerConfig } from './types/auth-server.js';
import {
  protectedResourceMetadataPath,
  type ProtectedResourceConfig,
} from './types/protected-resource.js';
import { createVerifyJwt } from './utils/create-verify-jwt.js';
import { transpileProtectedResourceMetadata } from './utils/transpile-protected-resource-metadata.js';
import { validateServerConfig } from './utils/validate-server-config.js';

export * from './types/oauth.js';
export * from './types/auth-server.js';
export * from './errors.js';
export * from './handlers/handle-bearer-auth.js';
export * from './utils/fetch-server-config.js';
export * from './utils/validate-server-config.js';
export * from './utils/create-verify-jwt.js';

/**
 * Config for the {@link MCPAuth} class.
 */
export type MCPAuthConfig =
  | { server: AuthServerConfig }
  | { protectedResource: ProtectedResourceConfig };

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
  /**
   * Deduplicated list of authorization servers, combined from:
   * 1. The configured auth server metadata (if provided)
   * 2. Authorization servers defined in protectedResource metadata
   *
   * These auth servers are used for dynamic JWT validation, where the issuer
   * in the JWT token is matched against available auth servers to find the
   * correct JWKS endpoint for token verification.
   */
  private readonly availableAuthServers: AuthServerConfig[];

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
    }

    this.availableAuthServers = this.getAuthServersFromConfig(config);
    this.validateAuthServers(this.availableAuthServers);
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
        cause: 'No authorization server is provided.',
      });
    }

    return createDelegatedRouter(this.config.server.metadata);
  }

  protectedResourceMetadataRouter(): Router {
    if (!('protectedResource' in this.config)) {
      throw new MCPAuthAuthServerError('invalid_server_config', {
        cause: 'No protected resource metadata is provided.',
      });
    }

    return createProtectedResourceMetadataRouter(
      transpileProtectedResourceMetadata(this.config.protectedResource.metadata)
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
     * @see {@link BearerAuthJwtConfig} for the available configuration options for JWT
     * verification.
     * @see {@link BearerAuthConfig} for the available configuration options (excluding
     * `verifyAccessToken` and `issuer`).
     */
    config?: Omit<BearerAuthConfig, 'verifyAccessToken' | 'issuer'> & BearerAuthJwtConfig
  ): RequestHandler;
  bearerAuth(
    modeOrVerify: VerifyAccessTokenMode | VerifyAccessTokenFunction,
    {
      jwtVerify,
      remoteJwkSet,
      ...config
    }: Omit<
      BearerAuthConfig,
      'verifyAccessToken' | 'issuer' | 'protectedResourceMetadataEndpoint'
    > &
      BearerAuthJwtConfig = {}
  ): RequestHandler {
    const getVerifyFunction = () => {
      if (typeof modeOrVerify === 'function') {
        return modeOrVerify;
      }

      switch (modeOrVerify) {
        case 'jwt': {
          return async (token: string) => {
            const unverifiedJwtPayload = decodeJwt(token);

            if (!unverifiedJwtPayload.iss) {
              throw new MCPAuthBearerAuthError('invalid_token', {
                cause: 'The JWT payload does not contain the `iss` field or it is malformed.',
              });
            }

            /**
             * This is a pre-check step before the actual verification of the JWT.
             * Validates the issuer before JWT verification to ensure we have a corresponding
             * authorization server with JWKS URI to verify the token.
             */
            this.validateIssuer(unverifiedJwtPayload.iss);

            const { jwksUri } = this.getAuthServerMetadataByIssuer(unverifiedJwtPayload.iss) ?? {};

            if (!jwksUri) {
              throw new MCPAuthAuthServerError('missing_jwks_uri');
            }

            return createVerifyJwt(
              createRemoteJWKSet(new URL(jwksUri), remoteJwkSet),
              jwtVerify
            )(token);
          };
        }
      }
    };

    return handleBearerAuth({
      verifyAccessToken: getVerifyFunction(),
      issuer: this.validateIssuer,
      protectedResourceMetadataEndpoint: cond(
        'protectedResource' in this.config &&
          new URL(
            protectedResourceMetadataPath,
            this.config.protectedResource.metadata.resource
          ).toString()
      ),
      ...config,
    });
  }

  private readonly getAuthServerMetadataByIssuer = (tokenIssuer: string) => {
    return this.availableAuthServers.find(
      (authServer) => authServer.metadata.issuer === tokenIssuer
    )?.metadata;
  };

  private readonly validateIssuer: ValidateIssuerFunction = (tokenIssuer: string) => {
    const authServer = this.getAuthServerMetadataByIssuer(tokenIssuer);

    if (!authServer) {
      throw new MCPAuthBearerAuthError('invalid_issuer', {
        expected: this.availableAuthServers
          .map((authServer) => authServer.metadata.issuer)
          .join(', '),
        actual: tokenIssuer,
      });
    }
  };

  private readonly getAuthServersFromConfig = (config: MCPAuthConfig) => {
    if ('server' in config) {
      return [config.server];
    }

    if ('protectedResource' in config) {
      return config.protectedResource.metadata.authorizationServers ?? [];
    }

    return [];
  };

  private readonly validateAuthServers = (authServers: AuthServerConfig[]) => {
    if (authServers.length === 0) {
      throw new MCPAuthAuthServerError('invalid_server_config', {
        cause: 'No authorization server is provided.',
      });
    }

    const uniqueAuthServers = new Map<string, AuthServerConfig>();

    for (const authServer of this.availableAuthServers) {
      const { issuer } = authServer.metadata;

      if (uniqueAuthServers.has(issuer)) {
        throw new MCPAuthAuthServerError('invalid_server_config', {
          cause: `The authorization server (issuer: \`${issuer}\`) is duplicated.`,
        });
      }

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
  };
}
