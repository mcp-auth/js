import cors from 'cors';
import { Router } from 'express';

import { metadataDiscoveryPath } from '../consts/mcp';
import { type AuthorizationServerMetadata } from '../oauth-types';

export const createDelegatedRouter = (metadata: AuthorizationServerMetadata): Router => {
  // eslint-disable-next-line new-cap
  const router = Router();

  router.get(metadataDiscoveryPath, cors(), (_, response) => {
    response.status(200).json(metadata);
  });

  return router;
};
