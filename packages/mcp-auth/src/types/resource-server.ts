import { type AuthServerConfig } from './auth-server.js';
import { type CamelCaseProtectedResourceMetadata } from './oauth.js';

/**
 * Configuration for protected resource servers (RFC 9728).
 */
export type ResourceServerConfig = {
  metadata: Omit<CamelCaseProtectedResourceMetadata, 'authorizationServers'> & {
    authorizationServers?: AuthServerConfig[];
  };
};
