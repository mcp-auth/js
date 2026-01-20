import { appendPath, joinPath } from '@silverhand/essentials';
import camelcaseKeys from 'camelcase-keys';

import { MCPAuthAuthServerError, MCPAuthConfigError } from '../errors.js';
import { type AuthServerType, type ResolvedAuthServerConfig } from '../types/auth-server.js';
import {
  type AuthorizationServerMetadata,
  authorizationServerMetadataSchema,
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
  /** The type of the remote authorization server. */
  type: AuthServerType;
  /**
   * A function to transpile the fetched metadata into the expected format. This is useful if the
   * server metadata does not conform to the standard schema or if you want to customize the
   * transformation of the metadata.
   */
  transpileData?: (
    // eslint-disable-next-line @typescript-eslint/ban-types
    data: object
  ) => MaybePromise<AuthorizationServerMetadata | Record<string, unknown>>;
};

/**
 * Fetches the server configuration from the provided well-known URL and validates it against the
 * MCP specification.
 *
 * If the server metadata does not conform to the expected schema, but you are sure that it is
 * compatible, you can define a `transpileData` function to transform the metadata into the
 * expected format.
 *
 * @param wellKnownUrl The well-known URL to fetch the server configuration from. This can be a
 * string or a URL object.
 * @param config The configuration object containing the server type and optional transpile function.
 * @returns A promise that resolves to the static server configuration with fetched metadata.
 * @throws {MCPAuthConfigError} if the fetch operation fails.
 * @throws {MCPAuthAuthServerError} if the server metadata is invalid or does not match the
 * MCP specification.
 */
export const fetchServerConfigByWellKnownUrl = async (
  wellKnownUrl: string | URL,
  { type, transpileData }: ServerMetadataConfig
): Promise<ResolvedAuthServerConfig> => {
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

  const parsed = authorizationServerMetadataSchema.safeParse(transpileData?.(metadata) ?? metadata);

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

/**
 * Fetches the server configuration according to the issuer and authorization server type.
 *
 * This function automatically determines the well-known URL based on the server type, as OAuth and
 * OpenID Connect servers have different conventions for their metadata endpoints.
 *
 * @see {@link fetchServerConfigByWellKnownUrl} for the underlying implementation.
 * @see {@link https://www.rfc-editor.org/rfc/rfc8414} for the OAuth 2.0 Authorization Server Metadata
 * specification.
 * @see {@link https://openid.net/specs/openid-connect-discovery-1_0.html} for the OpenID Connect
 * Discovery specification.
 *
 * @example
 * ```ts
 * import { fetchServerConfig } from 'mcp-auth';
 * // Fetching OAuth server configuration
 * // This will fetch the metadata from `https://auth.logto.io/.well-known/oauth-authorization-server/oauth`
 * const oauthConfig = await fetchServerConfig('https://auth.logto.io/oauth', { type: 'oauth' });
 *
 * // Fetching OpenID Connect server configuration
 * // This will fetch the metadata from `https://auth.logto.io/oidc/.well-known/openid-configuration`
 * const oidcConfig = await fetchServerConfig('https://auth.logto.io/oidc', { type: 'oidc' });
 *```
 *
 * @param issuer The issuer URL of the authorization server.
 * @param config The configuration object containing the server type and optional transpile function.
 * @returns A promise that resolves to the static server configuration with fetched metadata.
 * @throws {MCPAuthConfigError} if the fetch operation fails.
 * @throws {MCPAuthAuthServerError} if the server metadata is invalid or does not match the
 * MCP specification.
 */
export const fetchServerConfig = async (
  issuer: string,
  config: ServerMetadataConfig
): Promise<ResolvedAuthServerConfig> =>
  fetchServerConfigByWellKnownUrl(
    config.type === 'oauth' ? getOAuthWellKnownUrl(issuer) : getOidcWellKnownUrl(issuer),
    config
  );
