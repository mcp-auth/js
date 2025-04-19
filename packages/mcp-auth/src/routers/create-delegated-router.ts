import cors from 'cors';
import { Router } from 'express';
import snakecaseKeys from 'snakecase-keys';

import { type CamelCaseAuthorizationServerMetadata } from '../types/oauth.js';
import { serverMetadataPaths } from '../utils/fetch-server-config.js';

export const createDelegatedRouter = (metadata: CamelCaseAuthorizationServerMetadata): Router => {
  // eslint-disable-next-line new-cap
  const router = Router();

  router.get(serverMetadataPaths.oauth, cors(), (_, response) => {
    response.status(200).json(snakecaseKeys(metadata));
  });

  return router;
};
