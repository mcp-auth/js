import { type RequestHandler, type Router } from 'express';
import { createRemoteJWKSet, type RemoteJWKSetOptions, type JWTVerifyOptions } from 'jose';

import { MCPAuthAuthServerError } from './errors.js';
import {
  handleBearerAuth,
  type VerifyAccessTokenFunction,
  type BearerAuthConfig,
} from './handlers/handle-bearer-auth.js';
import { createDelegatedRouter } from './routers/create-delegated-router.js';
import { createProxyRouter, type ProxyModeConfig } from './routers/create-proxy-router.js';
import { type AuthServerConfig } from './types/auth-server.js';
import { createVerifyJwt } from './utils/create-verify-jwt.js';
import { validateServerConfig } from './utils/validate-server-config.js';

export * from './types/oauth.js';
export * from './types/auth-server.js';
export * from './errors.js';
export * from './handlers/handle-bearer-auth.js';
export * from './utils/fetch-server-config.js';
export * from './utils/validate-server-config.js';
export * from './utils/create-verify-jwt.js';

export type MCPAuthConfig = {
  server: AuthServerConfig;
};

type VerifyAccessTokenMode = 'jwt';

type AuthJwtConfig = {
  jwtVerify?: JWTVerifyOptions;
  remoteJwkSet?: RemoteJWKSetOptions;
};

export class MCPAuth {
  constructor(protected readonly config: MCPAuthConfig) {
    const result = validateServerConfig(config.server);

    if (!result.isValid) {
      throw new MCPAuthAuthServerError('invalid_server_config', {
        ...result,
      });
    }

    if (result.warnings.length > 0) {
      console.warn(
        `The authorization server configuration has warnings:\n\n  - ${result.warnings.join('\n  - ')}\n`
      );
    }
  }

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
    modeOrVerify: VerifyAccessTokenMode | VerifyAccessTokenFunction,
    {
      jwtVerify,
      remoteJwkSet,
      ...config
    }: Omit<BearerAuthConfig, 'verifyAccessToken' | 'issuer'> & AuthJwtConfig = {}
  ): RequestHandler {
    const { issuer, jwksUri } = this.config.server.metadata;

    const getVerifyFunction = () => {
      if (typeof modeOrVerify === 'function') {
        return modeOrVerify;
      }

      switch (modeOrVerify) {
        case 'jwt': {
          if (!jwksUri) {
            throw new MCPAuthAuthServerError('missing_jwks_uri');
          }

          return createVerifyJwt(createRemoteJWKSet(new URL(jwksUri), remoteJwkSet), jwtVerify);
        }
      }
    };

    return handleBearerAuth({
      verifyAccessToken: getVerifyFunction(),
      issuer,
      ...config,
    });
  }
}
