import { type CamelCaseAuthorizationServerMetadata } from './oauth.js';

export type AuthServerType = 'oauth' | 'oidc';

export type AuthServerConfig = {
  metadata: CamelCaseAuthorizationServerMetadata;
  type: AuthServerType;
};
