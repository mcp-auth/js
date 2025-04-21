import { appendPath, joinPath } from '@silverhand/essentials';
import camelcaseKeys from 'camelcase-keys';

import { MCPAuthAuthServerError, MCPAuthConfigError } from '../errors.js';
import { type AuthServerConfig, type AuthServerType } from '../types/auth-server.js';
import {
  type AuthorizationServerMetadata,
  authorizationServerMetadataSchemaGuard,
} from '../types/oauth.js';
import { type MaybePromise } from '../types/promise.js';

export const serverMetadataPaths = Object.freeze({
  oauth: '/.well-known/oauth-authorization-server',
  oidc: '/.well-known/openid-configuration',
} as const satisfies Record<AuthServerType, string>);

const getOAuthWellKnownUrl = (issuer: string) => {
  const url = new URL(issuer);
  const { pathname } = url;

  // eslint-disable-next-line @silverhand/fp/no-mutation
  url.pathname = joinPath(serverMetadataPaths.oauth, pathname);
  return url;
};

const getOidcWellKnownUrl = (issuer: string) =>
  appendPath(new URL(issuer), serverMetadataPaths.oidc);

type ServerMetadataConfig = {
  type: AuthServerType;

  transpileData?: (
    // eslint-disable-next-line @typescript-eslint/ban-types
    data: object
  ) => MaybePromise<AuthorizationServerMetadata | Record<string, unknown>>;
};

export const fetchServerConfigByWellKnownUrl = async (
  wellKnownUrl: string | URL,
  { type, transpileData }: ServerMetadataConfig
): Promise<AuthServerConfig> => {
  const response = await fetch(wellKnownUrl);

  if (!response.ok) {
    throw new MCPAuthConfigError(
      'fetch_server_config_error',
      `Failed to fetch server config from ${wellKnownUrl.toString()}: ${response.statusText}`
    );
  }

  const metadata: unknown = await response.json();

  if (typeof metadata !== 'object' || metadata === null) {
    throw new MCPAuthAuthServerError('invalid_server_metadata', {
      metadata,
      message: 'The server metadata is not a valid object or is null.',
    });
  }

  const parsed = authorizationServerMetadataSchemaGuard.safeParse(
    transpileData?.(metadata) ?? metadata
  );

  if (!parsed.success) {
    throw new MCPAuthAuthServerError('invalid_server_metadata', {
      metadata,
      parseError: parsed.error,
    });
  }

  return {
    metadata: camelcaseKeys(parsed.data),
    type,
  };
};

export const fetchServerConfig = async (
  issuer: string,
  config: ServerMetadataConfig
): Promise<AuthServerConfig> =>
  fetchServerConfigByWellKnownUrl(
    config.type === 'oauth' ? getOAuthWellKnownUrl(issuer) : getOidcWellKnownUrl(issuer),
    config
  );
