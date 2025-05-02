import { type RequestHandler, type Router } from 'express';
import { createRemoteJWKSet, type RemoteJWKSetOptions, type JWTVerifyOptions } from 'jose';

import { MCPAuthAuthServerError } from './errors.js';
import {
  handleBearerAuth,
  type VerifyAccessTokenFunction,
  type BearerAuthConfig,
} from './handlers/handle-bearer-auth.js';
import { createDelegatedRouter } from './routers/create-delegated-router.js';
import { type AuthServerConfig } from './types/auth-server.js';
import { createVerifyJwt } from './utils/create-verify-jwt.js';
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
export type MCPAuthConfig = {
  /**
   * Config for the remote authorization server.
   */
  server: AuthServerConfig;
};

export type VerifyAccessTokenMode = 'jwt';

/**
 * Configuration for the Bearer auth handler when using JWT verification.
 */
export type BearerAuthJwtConfig = {
  /**
   * Options to pass to the `jose` library's `jwtVerify` function.
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
 * The main class for the mcp-auth library, which provides methods to create routers for proxy mode
 * and delegated mode, as well as useful handlers for authentication and authorization in MCP
 * servers.
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
 * // Mount the proxy router to handle OAuth 2.0 Authorization Server Metadata and endpoints
 * app.use(mcpAuth.proxyRouter('http://localhost:3234');
 * // Alternatively, you can use the delegated router
 * // app.use(mcpAuth.delegatedRouter());
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
  constructor(protected readonly config: MCPAuthConfig) {
    const result = validateServerConfig(config.server);

    if (!result.isValid) {
      throw new MCPAuthAuthServerError('invalid_server_config', {
        ...result,
      });
    }

    if (result.warnings.length > 0) {
      console.warn(
        `The authorization server configuration has warnings:\n\n  - ${result.warnings.map(({ description }) => description).join('\n  - ')}\n`
      );
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
    return createDelegatedRouter(this.config.server.metadata);
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
    }: Omit<BearerAuthConfig, 'verifyAccessToken' | 'issuer'> & BearerAuthJwtConfig = {}
  ): RequestHandler {
    const { issuer, jwksUri } = this.config.server.metadata;

    const getVerifyFunction = () => {
      if (typeof modeOrVerify === 'function') {
        return modeOrVerify;
      }

      switch (modeOrVerify) {
        case 'jwt': {
          if (!jwksUri) {
            throw new MCPAuthAuthServerError('missing_jwks_uri');
          }

          return createVerifyJwt(createRemoteJWKSet(new URL(jwksUri), remoteJwkSet), jwtVerify);
        }
      }
    };

    return handleBearerAuth({
      verifyAccessToken: getVerifyFunction(),
      issuer,
      ...config,
    });
  }
}
