import type { RequestHandler, Router } from 'express';

import {
  AuthorizationServerHandler,
  type AuthServerModeConfig,
} from './auth/authorization-server-handler.js';
import { type MCPAuthHandler } from './auth/mcp-auth-handler.js';
import {
  ResourceServerHandler,
  type ResourceServerModeConfig,
} from './auth/resource-server-handler.js';
import { type VerifyJwtConfig } from './auth/token-verifier.js';
import { MCPAuthAuthServerError } from './errors.js';
import {
  handleBearerAuth,
  type VerifyAccessTokenFunction,
  type BearerAuthConfig,
} from './handlers/handle-bearer-auth.js';

export * from './types/oauth.js';
export * from './types/auth-server.js';
export * from './errors.js';
export * from './handlers/handle-bearer-auth.js';
export * from './utils/fetch-server-config.js';
export * from './utils/validate-server-config.js';
export * from './utils/create-verify-jwt.js';

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
 * ### Usage in `resource server` mode
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
 * ### Legacy Usage in `authorization server` mode (Deprecated)
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
  /**
   * The handler instance that manages mode-specific logic.
   */
  private readonly authHandler: MCPAuthHandler;

  /**
   * Creates an instance of MCPAuth.
   * It validates the entire configuration upfront to fail fast on errors.
   * @param config The authentication configuration.
   */
  constructor(public readonly config: MCPAuthConfig) {
    if ('server' in config) {
      this.authHandler = new AuthorizationServerHandler(config);
      return;
    }

    if (!('protectedResource' in config)) {
      throw new MCPAuthAuthServerError('invalid_server_config', {
        cause: 'No authorization server or protected resource metadata is provided.',
      });
    }

    this.authHandler = new ResourceServerHandler(config);
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
    return this.authHandler.delegatedRouter();
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
    return this.authHandler.protectedResourceMetadataRouter();
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
    /**
     * The `resource` property in the config is crucial for selecting the correct TokenVerifier
     * in `protectedResource` mode. This check ensures it's not forgotten.
     */
    if ('protectedResource' in this.config && !config.resource) {
      throw new MCPAuthAuthServerError('invalid_server_config', {
        cause:
          'A `resource` must be specified in the `bearerAuth` configuration when using a `protectedResource` configuration.',
      });
    }

    const tokenVerifier = this.authHandler.getTokenVerifier({ resource: config.resource });

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
}

export { type AuthServerModeConfig } from './auth/authorization-server-handler.js';
export { type ResourceServerModeConfig } from './auth/resource-server-handler.js';
