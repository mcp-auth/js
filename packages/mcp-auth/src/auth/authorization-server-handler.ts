import cors from 'cors';
import { Router, type Router as RouterType } from 'express';
import snakecaseKeys from 'snakecase-keys';

import { type AuthServerConfig } from '../types/auth-server.js';
import { serverMetadataPaths } from '../utils/fetch-server-config.js';
import { validateAuthServer } from '../utils/validate-auth-server.js';

import { AuthServerMetadataCache } from './auth-server-metadata-cache.js';
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

  /** Cache for auth server metadata, supporting discovery configs. */
  private readonly metadataCache = new AuthServerMetadataCache();

  constructor(private readonly config: AuthServerModeConfig) {
    super();

    console.warn(
      'The authorization server mode is deprecated. Please use resource server mode instead.'
    );
    validateAuthServer(config.server);
    this.tokenVerifier = new TokenVerifier([config.server]);
  }

  createMetadataRouter(): RouterType {
    // eslint-disable-next-line new-cap
    const router = Router();

    router.use(serverMetadataPaths.oauth, cors());
    router.get(serverMetadataPaths.oauth, async (_, response) => {
      const metadata = await this.metadataCache.getMetadata(this.config.server);
      response.status(200).json(snakecaseKeys(metadata));
    });

    return router;
  }

  /**
   * This is a dummy implementation that ignores the options, as there is only
   * one `TokenVerifier` in the authorization server mode.
   */
  getTokenVerifier(_options: GetTokenVerifierOptions): TokenVerifier {
    return this.tokenVerifier;
  }
}
