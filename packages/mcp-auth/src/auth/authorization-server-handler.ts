import { type Router } from 'express-serve-static-core';

import { MCPAuthAuthServerError } from '../errors.js';
import { createDelegatedRouter } from '../routers/create-delegated-router.js';
import { type AuthServerConfig } from '../types/auth-server.js';
import { validateAuthServer } from '../utils/validate-auth-server.js';

import { type MCPAuthHandler } from './mcp-auth-handler.js';
import { TokenVerifier } from './token-verifier.js';

/**
 * Configuration for the legacy, MCP server as authorization server mode.
 * @deprecated Use `ResourceServerModeConfig` config instead.
 */
export type AuthServerModeConfig = {
  /**
   * The single authorization server configuration.
   * @deprecated Use `protectedResource` config instead.
   */
  server: AuthServerConfig;
};

/**
 * Handles the authentication logic for the legacy `server` mode.
 * @deprecated
 */
export class AuthorizationServerHandler implements MCPAuthHandler {
  /** The `TokenVerifier` for the legacy `server` configuration. */
  private readonly tokenVerifier: TokenVerifier;

  constructor(private readonly config: AuthServerModeConfig) {
    console.warn(
      'the authorization server mode is deprecated. Please use resource server mode instead.'
    );
    validateAuthServer(config.server);
    this.tokenVerifier = new TokenVerifier([config.server]);
  }

  /**
   * Returns a router for serving the legacy OAuth 2.0 Authorization Server Metadata.
   * @throws {MCPAuthAuthServerError} If not supported in the current configuration.
   * @deprecated
   */
  delegatedRouter(): Router {
    return createDelegatedRouter(this.config.server.metadata);
  }

  protectedResourceMetadataRouter(): Router {
    throw new MCPAuthAuthServerError('invalid_server_config', {
      cause: '`protectedResourceMetadataRouter` is not available in `authorization server` mode.',
    });
  }

  getTokenVerifier(): TokenVerifier {
    return this.tokenVerifier;
  }
}
