import { condObject, pick } from '@silverhand/essentials';
import cors from 'cors';
import { Router, type Request as ExpressRequest, type Response as ExpressResponse } from 'express';
import { createProxyMiddleware, type Options } from 'http-proxy-middleware';
import snakecaseKeys from 'snakecase-keys';

import { defaultPaths } from '../consts/mcp.js';
import { type CamelCaseAuthorizationServerMetadata } from '../types/oauth.js';
import { serverMetadataPaths } from '../utils/fetch-server-config.js';

export type ProxyModeOverrides = Partial<{
  authorizationPath: string;
  tokenPath: string;
  registrationPath: string;
  revocationPath: string;
}>;

export type ProxyModeConfig = {
  /**
   * The base URL of the MCP server that will act as a proxy for the remote authorization server.
   * This URL is used to construct the full URLs in the OAuth 2.0 Authorization Server Metadata
   * response.
   *
   * It should be the URL where the MCP server is hosted, including the protocol (e.g., `https://example.com`).
   */
  baseUrl: string;
  /**
   * The metadata of the remote authorization server in camelCase format. It will be used for
   * the response to the OAuth 2.0 Authorization Server Metadata endpoint and for proxying requests
   * to the authorization server endpoints.
   *
   * The metadata can be provided by:
   * - Using the `fetchServerConfig` or `fetchServerConfigByWellKnownUrl` utility functions to fetch
   * the metadata from a remote server.
   * - Manually inputting the metadata in camelCase format.
   */
  metadata: CamelCaseAuthorizationServerMetadata;
  /**
   * The overrides for the proxy mode configuration. These allow customization of the paths used
   * by the proxy router for the authorization server endpoints.
   *
   * If a path is not provided, the default paths from {@link defaultPaths} will be used.
   */
  overrides?: ProxyModeOverrides;
  /**
   * Additional options for the proxy middleware (`http-proxy-middleware`).
   * These options can be used to customize the behavior of the proxy, such as changing the target,
   * modifying headers, or handling errors.
   *
   * **Caution**: Be careful when overriding the existing options, especially the `on.proxyRes`
   * handler, as they may impact the normal operation of the proxy.
   */
  proxyOptions?: Options<ExpressRequest, ExpressResponse>;
};

/**
 * Creates a proxy router that serves the OAuth 2.0 Authorization Server Metadata and proxies
 * requests to the remote authorization server endpoints.
 *
 * This router is designed to work in a proxy mode, where the MCP server acts as an
 * OAuth authorization server for MCP clients, forwarding requests to a remote
 * authorization server.
 *
 * The router provides the following endpoints:
 *
 * - `/.well-known/oauth-authorization-server`: Returns the OAuth 2.0 Authorization Server
 *   Metadata. It includes transpiled metadata from the remote authorization server, updating the
 *   base URLs and paths to match the MCP server's configuration.
 * - Proxy endpoints for the authorization, token, registration, and revocation paths defined in
 *   the `metadata` parameter. If some of optional endpoints are not defined in the metadata,
 *   they will not be proxied.
 *
 * @remarks
 * The metadata can be provided by:
 * - Using the `fetchServerConfig` or `fetchServerConfigByWellKnownUrl` utility functions to fetch
 * the metadata from a remote server.
 * - Manually inputting the metadata in camelCase format.
 *
 * @example
 * ```ts
 * import { createProxyRouter, fetchServerConfig } from 'mcp-auth';
 * import express from 'express';
 *
 * const metadata = await fetchServerConfig('https://logto.io', { type: 'oauth' });
 * const proxyRouter = createProxyRouter({
 *   baseUrl: 'https://your-mcp-server.com',
 *   metadata,
 * });
 * const app = express();
 * app.use('/auth', proxyRouter);
 * ```
 *
 * @param param0 The configuration for the proxy router.
 * @returns An Express router that serves the OAuth 2.0 Authorization Server Metadata and proxies
 * requests to the remote authorization server endpoints.
 */
export const createProxyRouter = ({
  baseUrl,
  metadata,
  overrides,
  proxyOptions,
}: ProxyModeConfig): Router => {
  const authorizationPath = overrides?.authorizationPath ?? defaultPaths.authorizationPath;
  const tokenPath = overrides?.tokenPath ?? defaultPaths.tokenPath;
  const registrationPath =
    metadata.registrationEndpoint && (overrides?.registrationPath ?? defaultPaths.registrationPath);
  const revocationPath =
    metadata.revocationEndpoint && (overrides?.revocationPath ?? defaultPaths.revocationPath);

  /**
   * The metadata for the MCP server acting as an OAuth authorization server. This metadata is
   * transformed from the remote authorization server's metadata for proxy mode.
   *
   * The content of this metadata is based on the MCP SDK implementation, but instead of overriding
   * some fields (like `grant_types_supported`), it uses the original metadata from the remote
   * authorization server and only alters necessary fields for the MCP server to function correctly
   * as a proxy.
   *
   * @see [GitHub permlink](https://github.com/modelcontextprotocol/typescript-sdk/blob/64653f54bd69ec2f6703f7c1e0745f84d220bea7/src/server/auth/router.ts#L69-L85) for the original implementation.
   */
  const serverMetadata: Readonly<CamelCaseAuthorizationServerMetadata> = Object.freeze({
    ...pick(
      metadata,
      'opPolicyUri',
      'opTosUri',
      'serviceDocumentation',
      'scopeSupported',
      'responseTypesSupported',
      'codeChallengeMethodsSupported',
      'grantTypesSupported',
      'tokenEndpointAuthMethodsSupported',
      'revocationEndpointAuthMethodsSupported'
    ),
    issuer: metadata.issuer,
    authorizationEndpoint: new URL(authorizationPath, baseUrl).href,
    tokenEndpoint: new URL(tokenPath, baseUrl).href,
    registrationEndpoint: registrationPath && new URL(registrationPath, baseUrl).href,
    revocationEndpoint: revocationPath && new URL(revocationPath, baseUrl).href,
  });

  // eslint-disable-next-line new-cap
  const router = Router();

  router.get(serverMetadataPaths.oauth, cors(), (_, response) => {
    response.status(200).json(snakecaseKeys(condObject(serverMetadata)));
  });

  // eslint-disable-next-line no-restricted-syntax -- It's a string array
  const paths = [authorizationPath, tokenPath, registrationPath, revocationPath].filter(
    Boolean
  ) as string[];
  const { origin: issuerOrigin } = new URL(metadata.issuer);

  router.use(
    createProxyMiddleware({
      target: issuerOrigin,
      changeOrigin: true,
      pathFilter: (pathname) => paths.includes(pathname),
      pathRewrite: (pathWithQuery, request) => {
        // `pathWithQuery` is the full path including query parameters, and `request.path` is the
        // parsed path without query parameters.
        // We need to rewrite the path based on the metadata endpoints and keep the query
        // parameters intact.
        const { path } = request;

        if (path === authorizationPath) {
          return pathWithQuery.replace(path, new URL(metadata.authorizationEndpoint).pathname);
        }

        if (path === tokenPath) {
          return pathWithQuery.replace(path, new URL(metadata.tokenEndpoint).pathname);
        }

        if (registrationPath && path === registrationPath && metadata.registrationEndpoint) {
          return pathWithQuery.replace(path, new URL(metadata.registrationEndpoint).pathname);
        }

        if (revocationPath && path === revocationPath && metadata.revocationEndpoint) {
          return pathWithQuery.replace(path, new URL(metadata.revocationEndpoint).pathname);
        }
      },
      ...proxyOptions, // Order matters! Don't override `on` handlers since we need to modify the `location` header.
      on: {
        proxyRes: (proxyResponse) => {
          const { location } = proxyResponse.headers;
          if (location) {
            // eslint-disable-next-line @silverhand/fp/no-mutation -- Business need
            proxyResponse.headers.location = new URL(location, issuerOrigin).href;
          }
        },
        ...proxyOptions?.on,
      },
    })
  );

  return router;
};
