import cors from 'cors';
import { Router } from 'express';
import snakecaseKeys from 'snakecase-keys';

import { type CamelCaseProtectedResourceMetadata } from '../types/oauth.js';
import { createResourceMetadataEndpoint } from '../utils/create-resource-metadata-endpoint.js';

/**
 * Creates a protected resource metadata router that serves the OAuth 2.0 Protected Resource Metadata endpoint with
 * the provided metadata.
 *
 * @remarks
 * The metadata can be provided in two ways:
 * 1. Directly as standard OAuth 2.0 Protected Resource Metadata format (with authorization servers as issuer strings)
 * 2. Through MCPAuth's `protectedResource` config, which needs to be transformed by {@link transpileResourceMetadata}
 *    to convert the config format to the standard format.
 *
 * @example
 * ```ts
 * // Method 1: Using standard OAuth 2.0 Protected Resource Metadata directly
 * import express from 'express';
 * import { createProtectedResourceMetadataRouter } from 'mcp-auth';
 *
 * const router = createProtectedResourceMetadataRouter({
 *   resource: 'https://api.example.com',
 *   authorizationServers: ['https://auth.example.com'], // Standard format with issuer strings
 *   scopesSupported: ['read', 'write'],
 * });
 *
 * // Method 2: Using MCPAuth's protectedResource config (will be transformed)
 * import { MCPAuth, fetchServerConfig } from 'mcp-auth';
 *
 * const authServerConfig = await fetchServerConfig('https://auth.example.com', { type: 'oidc' });
 *
 * const protectedResourceConfig = {
 *   metadata: {
 *     resource: 'https://api.example.com',
 *     authorizationServers: [authServerConfig],
 *     scopesSupported: ['read', 'write'],
 *   },
 * };
 *
 * const router = createResourceMetadataRouter(
 *   transpileResourceMetadata(protectedResourceConfig)
 * );
 * ```
 *
 * @param metadataList The metadata in standard OAuth 2.0 Protected Resource Metadata format (with authorization
 * servers as issuer strings). If you're using MCPAuth's config format, use {@link transpileResourceMetadata}
 * first to convert it to the standard format.
 * @returns An Express router that serves the metadata at the {@link resourceMetadataPath}
 * endpoint (`/.well-known/oauth-protected-resource`).
 */
export const createResourceMetadataRouter = (
  metadataList: CamelCaseProtectedResourceMetadata[]
): Router => {
  // eslint-disable-next-line new-cap
  const router = Router();

  for (const metadata of metadataList) {
    const resourceMetadataEndpoint = createResourceMetadataEndpoint(metadata.resource);

    // Enable CORS for the metadata endpoint, as it's intended for public consumption.
    router.use(resourceMetadataEndpoint.pathname, cors());
    router.get(resourceMetadataEndpoint.pathname, (_, response) => {
      response.status(200).json(snakecaseKeys(metadata));
    });
  }

  return router;
};
