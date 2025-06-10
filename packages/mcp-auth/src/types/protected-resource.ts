import { type AuthServerConfig } from './auth-server.js';
import { type CamelCaseProtectedResourceMetadata } from './oauth.js';

/**
 * Configuration for protected resource servers (RFC 9728).
 */
export type ProtectedResourceConfig = {
  metadata: Omit<CamelCaseProtectedResourceMetadata, 'authorizationServers'> & {
    authorizationServers?: AuthServerConfig[];
  };
};

export const protectedResourceMetadataPath = '/.well-known/oauth-protected-resource';
