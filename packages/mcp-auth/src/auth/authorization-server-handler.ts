import { type Router } from 'express';

import { createDelegatedRouter } from '../routers/create-delegated-router.js';
import { type AuthServerConfig } from '../types/auth-server.js';
import { validateAuthServer } from '../utils/validate-auth-server.js';

import { MCPAuthHandler } from './mcp-auth-handler.js';
import { type GetTokenVerifierOptions, TokenVerifier } from './token-verifier.js';

/**
 * Configuration for the legacy, MCP server as authorization server mode.
 * @deprecated Use `ResourceServerModeConfig` config instead.
 */
export type AuthServerModeConfig = {
  /**
   * The single authorization server configuration.
   * @deprecated Use `protectedResources` config instead.
   */
  server: AuthServerConfig;
};

/**
 * Handles the authentication logic for the legacy `server` mode.
 * @deprecated
 */
export class AuthorizationServerHandler extends MCPAuthHandler {
  /** The `TokenVerifier` for the legacy `server` configuration. */
  private readonly tokenVerifier: TokenVerifier;

  constructor(private readonly config: AuthServerModeConfig) {
    super();

    console.warn(
      'The authorization server mode is deprecated. Please use resource server mode instead.'
    );
    validateAuthServer(config.server);
    this.tokenVerifier = new TokenVerifier([config.server]);
  }

  createMetadataRouter(): Router {
    return createDelegatedRouter(this.config.server.metadata);
  }

  /**
   * This is a dummy implementation that ignores the options, as there is only
   * one `TokenVerifier` in the authorization server mode.
   */
  getTokenVerifier(_options: GetTokenVerifierOptions): TokenVerifier {
    return this.tokenVerifier;
  }
}
