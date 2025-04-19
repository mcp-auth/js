import { condObject, pick } from '@silverhand/essentials';
import cors from 'cors';
import { Router } from 'express';
import { createProxyMiddleware } from 'http-proxy-middleware';
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
  baseUrl: string;
  metadata: CamelCaseAuthorizationServerMetadata;
  overrides?: ProxyModeOverrides;
};

export const createProxyRouter = ({ baseUrl, metadata, overrides }: ProxyModeConfig): Router => {
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

  // Create the proxy mode router
  // eslint-disable-next-line new-cap
  const router = Router();

  router.get(serverMetadataPaths.oauth, cors(), (_, response) => {
    response.status(200).json(snakecaseKeys(condObject(serverMetadata)));
  });

  router.use(
    createProxyMiddleware({
      // eslint-disable-next-line no-restricted-syntax -- It is a string array
      pathFilter: [authorizationPath, tokenPath, registrationPath, revocationPath].filter(
        Boolean
      ) as string[],
      pathRewrite: (path) => {
        if (path === authorizationPath) {
          return metadata.authorizationEndpoint;
        }

        if (path === tokenPath) {
          return metadata.tokenEndpoint;
        }

        if (registrationPath && path === registrationPath) {
          return metadata.registrationEndpoint;
        }

        if (revocationPath && path === revocationPath) {
          return metadata.revocationEndpoint;
        }

        return path;
      },
    })
  );

  return router;
};
