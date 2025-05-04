import cors from 'cors';
import { Router } from 'express';
import snakecaseKeys from 'snakecase-keys';

import { type CamelCaseAuthorizationServerMetadata } from '../types/oauth.js';
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

  router.use(serverMetadataPaths.oauth, cors());
  router.get(serverMetadataPaths.oauth, cors(), (_, response) => {
    response.status(200).json(snakecaseKeys(metadata));
  });

  return router;
};
