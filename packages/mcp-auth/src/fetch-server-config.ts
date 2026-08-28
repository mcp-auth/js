import { MCPAuthAuthServerError, MCPAuthConfigError } from './errors.js';
import { type AuthServerType, type ResolvedAuthServerConfig } from './types.js';
import { parseAuthServerMetadata } from './validate-auth-server.js';

export const serverMetadataPaths = Object.freeze({
  oauth: '/.well-known/oauth-authorization-server',
  oidc: '/.well-known/openid-configuration',
} as const satisfies Record<AuthServerType, string>);

/** Joins path segments with a single `/` separator, dropping empty segments. */
const joinPaths = (...segments: string[]): string =>
  '/' +
  segments
    .flatMap((segment) => segment.split('/'))
    .filter(Boolean)
    .join('/');

const getWellKnownUrl = (issuer: string, type: AuthServerType): URL => {
  const url = new URL(issuer);

  /*
   * OAuth 2.0 (RFC 8414) inserts the well-known path between the origin and the issuer path,
   * while OpenID Connect Discovery appends it after the issuer path.
   */
  // eslint-disable-next-line @silverhand/fp/no-mutation
  url.pathname =
    type === 'oauth'
      ? joinPaths(serverMetadataPaths.oauth, url.pathname)
      : joinPaths(url.pathname, serverMetadataPaths.oidc);
  return url;
};

export type ServerMetadataConfig = {
  /** The type of the remote authorization server. */
  type: AuthServerType;
  /**
   * A function to transpile the fetched metadata into the expected format. This is useful if the
   * server metadata does not conform to the standard schema or if you want to customize the
   * transformation of the metadata. The function may be synchronous or return a promise.
   */
  // eslint-disable-next-line @typescript-eslint/ban-types
  transpileData?: (data: object) => Record<string, unknown> | Promise<Record<string, unknown>>;
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
 * @returns A promise that resolves to the resolved server configuration with fetched metadata.
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

  const data: unknown = await response.json();
  const metadata = parseAuthServerMetadata(
    typeof data === 'object' && data !== null && transpileData ? await transpileData(data) : data
  );

  return { metadata, type };
};

/**
 * Fetches the server configuration according to the issuer and authorization server type.
 *
 * This function automatically determines the well-known URL based on the server type, as OAuth
 * and OpenID Connect servers have different conventions for their metadata endpoints. It also
 * validates that the `issuer` field in the fetched metadata matches the expected issuer, as
 * required by RFC 8414 and OpenID Connect Discovery.
 *
 * @see {@link fetchServerConfigByWellKnownUrl} for the underlying implementation, which can be
 * used directly when the well-known URL differs from the standard conventions (no issuer match
 * validation is performed in that case).
 * @see {@link https://www.rfc-editor.org/rfc/rfc8414} for the OAuth 2.0 Authorization Server
 * Metadata specification.
 * @see {@link https://openid.net/specs/openid-connect-discovery-1_0.html} for the OpenID Connect
 * Discovery specification.
 *
 * @example
 * ```ts
 * import { fetchServerConfig } from 'mcp-auth';
 *
 * // Fetching OAuth server configuration
 * // This fetches the metadata from `https://auth.logto.io/.well-known/oauth-authorization-server/oauth`
 * const oauthConfig = await fetchServerConfig('https://auth.logto.io/oauth', { type: 'oauth' });
 *
 * // Fetching OpenID Connect server configuration
 * // This fetches the metadata from `https://auth.logto.io/oidc/.well-known/openid-configuration`
 * const oidcConfig = await fetchServerConfig('https://auth.logto.io/oidc', { type: 'oidc' });
 * ```
 *
 * @param issuer The issuer URL of the authorization server.
 * @param config The configuration object containing the server type and optional transpile function.
 * @returns A promise that resolves to the resolved server configuration with fetched metadata.
 * @throws {MCPAuthConfigError} if the fetch operation fails.
 * @throws {MCPAuthAuthServerError} if the server metadata is invalid, does not match the
 * MCP specification, or its issuer does not match the expected issuer.
 */
export const fetchServerConfig = async (
  issuer: string,
  config: ServerMetadataConfig
): Promise<ResolvedAuthServerConfig> => {
  const result = await fetchServerConfigByWellKnownUrl(
    getWellKnownUrl(issuer, config.type),
    config
  );

  if (result.metadata.issuer !== issuer) {
    throw new MCPAuthAuthServerError('invalid_server_metadata', {
      message: `The server metadata issuer (\`${result.metadata.issuer}\`) does not match the expected issuer (\`${issuer}\`).`,
    });
  }

  return result;
};
