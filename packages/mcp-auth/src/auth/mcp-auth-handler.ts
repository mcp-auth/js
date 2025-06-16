import { type Optional } from '@silverhand/essentials';
import { type Router } from 'express';

import type { TokenVerifier } from './token-verifier.js';

/**
 * Defines the contract for a handler that manages the logic for a specific MCPAuth configuration.
 * This allows for clean separation of logic between legacy and modern configurations.
 */
export abstract class MCPAuthHandler {
  /**
   * Returns a router for serving either the legacy OAuth 2.0 Authorization Server Metadata or
   * the OAuth 2.0 Protected Resource Metadata, depending on the configuration.
   */
  abstract createMetadataRouter(): Router;
  /**
   * Resolves the appropriate TokenVerifier based on the provided options.
   * @param options - Optional parameters, usage depends on implementation.
   */
  abstract getTokenVerifier(options: Optional<{ resource?: string }>): TokenVerifier;
}
