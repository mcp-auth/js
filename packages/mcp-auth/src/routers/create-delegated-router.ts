import cors from 'cors';
import { Router } from 'express';
import snakecaseKeys from 'snakecase-keys';

import {
  type CamelCaseProtectedResourceMetadata,
  type CamelCaseAuthorizationServerMetadata,
} from '../types/oauth.js';
import { protectedResourceMetadataPath } from '../types/protected-resource.js';
import { serverMetadataPaths } from '../utils/fetch-server-config.js';

/**
 * Creates a delegated router that serves the OAuth 2.0 Authorization Server Metadata endpoint with
 * the provided metadata.
 *
 * @remarks
 * The metadata can be provided by:
 * - Using the `fetchServerConfig` or `fetchServerConfigByWellKnownUrl` utility functions to fetch
 * the metadata from a remote server.
 * - Manually inputting the metadata in camelCase format.
 *
 * @example
 * ```ts
 * import { createDelegatedRouter, fetchServerConfig } from 'mcp-auth';
 * import { express } from 'express';
 *
 * const metadata = await fetchServerConfig('https://logto.io', { type: 'oidc' });
 * const delegatedRouter = createDelegatedRouter(metadata);
 * const app = express();
 * app.use('/auth', delegatedRouter);
 * ```
 *
 * @param metadata The metadata of the authorization server in camelCase format.
 * @returns An Express router that serves the metadata at the {@link serverMetadataPaths.oauth}
 * endpoint.
 */
export const createDelegatedRouter = (metadata: CamelCaseAuthorizationServerMetadata): Router => {
  // eslint-disable-next-line new-cap
  const router = Router();

  // Apply CORS middleware to allow cross-origin requests to the OAuth metadata endpoint.
  router.use(serverMetadataPaths.oauth, cors());
  router.get(serverMetadataPaths.oauth, (_, response) => {
    response.status(200).json(snakecaseKeys(metadata));
  });

  return router;
};

/**
 * Creates a protected resource metadata router that serves the OAuth 2.0 Protected Resource Metadata endpoint with
 * the provided metadata.
 *
 * @remarks
 * The metadata can be provided in two ways:
 * 1. Directly as standard OAuth 2.0 Protected Resource Metadata format (with authorization servers as issuer strings)
 * 2. Through MCPAuth's `protectedResource` config, which needs to be transformed by {@link transpileProtectedResourceMetadata}
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
 * const router = createProtectedResourceMetadataRouter(
 *   transpileProtectedResourceMetadata(protectedResourceConfig)
 * );
 * ```
 *
 * @param metadata The metadata in standard OAuth 2.0 Protected Resource Metadata format (with authorization
 * servers as issuer strings). If you're using MCPAuth's config format, use {@link transpileProtectedResourceMetadata}
 * first to convert it to the standard format.
 * @returns An Express router that serves the metadata at the {@link protectedResourceMetadataPath}
 * endpoint (`/.well-known/oauth-protected-resource`).
 */
export const createProtectedResourceMetadataRouter = (
  metadata: CamelCaseProtectedResourceMetadata
): Router => {
  // eslint-disable-next-line new-cap
  const router = Router();

  // Apply CORS middleware to allow cross-origin requests to the protected resource metadata endpoint.
  router.use(protectedResourceMetadataPath, cors());
  router.get(protectedResourceMetadataPath, (_, response) => {
    response.status(200).json(snakecaseKeys(metadata));
  });

  return router;
};
