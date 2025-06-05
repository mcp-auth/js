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
 * @param serverMetadata The metadata of the authorization server in camelCase format.
 * @returns An Express router that serves the metadata at the {@link serverMetadataPaths.oauth}
 * endpoint.
 */
export const createDelegatedRouter = ({
  serverMetadata,
  protectedResourceMetadata,
}: {
  serverMetadata?: CamelCaseAuthorizationServerMetadata;
  protectedResourceMetadata?: CamelCaseProtectedResourceMetadata;
}): Router => {
  // eslint-disable-next-line new-cap
  const router = Router();

  if (serverMetadata) {
    // Apply CORS middleware to allow cross-origin requests to the OAuth metadata endpoint.
    router.use(serverMetadataPaths.oauth, cors());
    router.get(serverMetadataPaths.oauth, (_, response) => {
      response.status(200).json(snakecaseKeys(serverMetadata));
    });
  }

  if (protectedResourceMetadata) {
    // Apply CORS middleware to allow cross-origin requests to the protected resource metadata endpoint.
    router.use(protectedResourceMetadataPath, cors());
    router.get(protectedResourceMetadataPath, (_, response) => {
      response.status(200).json(snakecaseKeys(protectedResourceMetadata));
    });
  }

  return router;
};
