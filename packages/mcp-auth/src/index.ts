import { type RequestHandler, type Router } from 'express';

import {
  handleBearerAuth,
  type VerifyAccessTokenFunction,
  type AuthInfo,
  type BearerAuthConfig,
} from './handlers/handle-bearer-auth';
import { type AuthorizationServerMetadata } from './oauth-types';
import { createDelegatedRouter } from './routers/create-delegated-router';
import { createProxyRouter, type ProxyModeConfig } from './routers/create-proxy-router';
import { verifyJwt } from './utils/verify-jwt';
import { verifyOpaqueToken } from './utils/verify-opaque-token';

export type AuthServerConfig = {
  metadata: AuthorizationServerMetadata;
  type?: 'oauth' | 'oidc';
};

export type MCPAuthConfig = {
  server: AuthServerConfig;
};

const getVerifyFunction = (
  modeOrVerify: 'opaque' | 'jwt' | VerifyAccessTokenFunction
): VerifyAccessTokenFunction => {
  if (typeof modeOrVerify === 'function') {
    return modeOrVerify;
  }

  switch (modeOrVerify) {
    case 'opaque': {
      return verifyOpaqueToken;
    }
    case 'jwt': {
      return verifyJwt;
    }
  }
};

export class MCPAuth {
  constructor(protected readonly config: MCPAuthConfig) {}

  proxyRouter(
    baseUrl: string,
    config?: Partial<Omit<ProxyModeConfig, 'baseUrl' | 'metadata'>>
  ): Router {
    return createProxyRouter({
      baseUrl,
      metadata: this.config.server.metadata,
      ...config,
    });
  }

  delegatedRouter(): Router {
    return createDelegatedRouter(this.config.server.metadata);
  }

  bearerAuth(
    modeOrVerify: 'opaque' | 'jwt' | ((token: string) => PromiseLike<AuthInfo>),
    config: Omit<BearerAuthConfig, 'verifyAccessToken' | 'issuer'>
  ): RequestHandler {
    return handleBearerAuth({
      verifyAccessToken: getVerifyFunction(modeOrVerify),
      issuer: this.config.server.metadata.issuer,
      ...config,
    });
  }
}
