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

  // eslint-disable-next-line new-cap
  const router = Router();

  router.get(serverMetadataPaths.oauth, cors(), (_, response) => {
    response.status(200).json(snakecaseKeys(condObject(serverMetadata)));
  });

  // eslint-disable-next-line no-restricted-syntax -- It's a string array
  const paths = [authorizationPath, tokenPath, registrationPath, revocationPath].filter(
    Boolean
  ) as string[];

  router.use(
    createProxyMiddleware({
      target: metadata.issuer,
      pathFilter: (pathname) => paths.includes(pathname),
      pathRewrite: (_, request) => {
        const { path } = request;

        if (path === authorizationPath) {
          return new URL(metadata.authorizationEndpoint).pathname;
        }

        if (path === tokenPath) {
          return new URL(metadata.tokenEndpoint).pathname;
        }

        if (registrationPath && path === registrationPath) {
          return metadata.registrationEndpoint && new URL(metadata.registrationEndpoint).pathname;
        }

        if (revocationPath && path === revocationPath) {
          return metadata.revocationEndpoint && new URL(metadata.revocationEndpoint).pathname;
        }
      },
    })
  );

  return router;
};
