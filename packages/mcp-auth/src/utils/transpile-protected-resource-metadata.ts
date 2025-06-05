import { type CamelCaseProtectedResourceMetadata } from '../types/oauth.js';
import { type ProtectedResourceConfig } from '../types/protected-resource.js';

export const transpileProtectedResourceMetadata = (
  metadata: ProtectedResourceConfig['metadata']
): CamelCaseProtectedResourceMetadata => ({
  ...metadata,
  authorizationServers: metadata.authorizationServers?.map((server) => server.metadata.issuer),
});
