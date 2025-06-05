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
import { createDelegatedRouter } from './routers/create-delegated-router.js';
import { type AuthServerConfig } from './types/auth-server.js';
import {
  protectedResourceMetadataPath,
  type ProtectedResourceConfig,
} from './types/protected-resource.js';
import { createVerifyJwt } from './utils/create-verify-jwt.js';
import { deduplicateAuthServers } from './utils/deduplicate-auth-servers.js';
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
 * Supports two modes:
 * 1. Full mode: both authorization server and protected resource server configs
 * 2. Single role mode: either authorization server or protected resource server config
 *
 * @property server - Config for the remote authorization server.
 * @property protectedResource - Config for the MCP Server when acting as an OAuth 2.0 protected resource server.
 */
export type MCPAuthConfig =
  | {
      server: AuthServerConfig;
      protectedResource: ProtectedResourceConfig;
    }
  | {
      server: AuthServerConfig;
      protectedResource?: ProtectedResourceConfig;
    }
  | {
      server?: AuthServerConfig;
      protectedResource: ProtectedResourceConfig;
    };

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
    const { server, protectedResource } = config;
    if (!server && !protectedResource) {
      throw new MCPAuthAuthServerError('invalid_server_config', {
        cause: 'No authorization server or protected resource metadata is provided.',
      });
    }

    this.availableAuthServers = deduplicateAuthServers(
      [server, ...(protectedResource?.metadata.authorizationServers ?? [])].filter(
        // eslint-disable-next-line unicorn/prefer-native-coercion-functions
        (item): item is AuthServerConfig => Boolean(item)
      )
    );

    for (const authServer of this.availableAuthServers) {
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

  /**
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
    const { server, protectedResource } = this.config;

    return createDelegatedRouter({
      serverMetadata: server?.metadata,
      protectedResourceMetadata: cond(
        protectedResource?.metadata &&
          transpileProtectedResourceMetadata(protectedResource.metadata)
      ),
    });
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
      'verifyAccessToken' | 'validateIssuer' | 'protectedResourceMetadataEndpoint'
    > &
      BearerAuthJwtConfig = {}
  ): RequestHandler {
    const { server, protectedResource } = this.config;

    if (!server && !protectedResource) {
      throw new MCPAuthAuthServerError('invalid_server_config');
    }

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

            const authServer = this.getAuthServerMetadataByIssuer(unverifiedJwtPayload.iss);

            if (!authServer) {
              throw new MCPAuthBearerAuthError('invalid_issuer', {
                expected: this.availableAuthServers
                  .map((authServer) => authServer.metadata.issuer)
                  .join(', '),
                actual: unverifiedJwtPayload.iss,
              });
            }

            const { jwksUri } = authServer;

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
      validateIssuer: this.validateIssuer,
      protectedResourceMetadataEndpoint: cond(
        protectedResource &&
          new URL(protectedResourceMetadataPath, protectedResource.metadata.resource).toString()
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
}
