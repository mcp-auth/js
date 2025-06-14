import { type Router } from 'express';

import type { TokenVerifier } from './token-verifier.js';

/**
 * Defines the contract for a handler that manages the logic for a specific MCPAuth configuration.
 * This allows for clean separation of logic between legacy and modern configurations.
 */
export type MCPAuthHandler = {
  /**
   * Returns a router for serving the legacy OAuth 2.0 Authorization Server Metadata.
   * @throws {MCPAuthAuthServerError} If not supported in the current configuration.
   * @deprecated Use `protectedResourceMetadataRouter` instead.
   */
  delegatedRouter(): Router;
  /**
   * Returns a router for serving the OAuth 2.0 Protected Resource Metadata.
   * @throws {MCPAuthAuthServerError} If not supported in the current configuration.
   */
  protectedResourceMetadataRouter(): Router;
  /**
   * Resolves the appropriate TokenVerifier based on the provided options.
   * @param options - Options containing the resource identifier for verifier lookup.
   */
  getTokenVerifier(options: { resource?: string }): TokenVerifier;
};
