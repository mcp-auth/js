import {
  createRemoteJWKSet,
  decodeJwt,
  type JWTVerifyOptions,
  type RemoteJWKSetOptions,
} from 'jose';

import { MCPAuthAuthServerError, MCPAuthBearerAuthError } from '../errors.js';
import { type AuthServerConfig } from '../types/auth-server.js';
import { createVerifyJwt } from '../utils/create-verify-jwt.js';

/**
 * Configuration for creating a JWT verification function.
 */
export type VerifyJwtConfig = {
  /**
   * Options to pass to the `jose` library's `jwtVerify` function.
   *
   * The issuer option is hardcoded to the authorization server’s issuer.
   *
   * @see {@link JWTVerifyOptions} for the type definition of the options.
   */
  jwtVerify?: JWTVerifyOptions;
  /**
   * Options to pass to the `jose` library's `createRemoteJWKSet` function.
   *
   * @see {@link RemoteJWKSetOptions} for the type definition of the options.
   */
  remoteJwkSet?: RemoteJWKSetOptions;
};

export class TokenVerifier {
  constructor(private readonly authServers: AuthServerConfig[]) {}

  createVerifyJwtFunction =
    ({ jwtVerify, remoteJwkSet }: VerifyJwtConfig) =>
    async (token: string) => {
      const unverifiedIssuer = this.getUnverifiedJwtIssuer(token);
      /**
       * This is a pre-check step before the actual verification of the JWT.
       * Validates the issuer before JWT verification to ensure we have a corresponding
       * authorization server with JWKS URI to verify the token.
       */
      this.validateJwtIssuer(unverifiedIssuer);

      const { jwksUri } = this.getAuthServerMetadataByIssuer(unverifiedIssuer) ?? {};

      if (!jwksUri) {
        throw new MCPAuthAuthServerError('missing_jwks_uri', {
          cause: `The authorization server (\`${unverifiedIssuer}\`) does not have a JWKS URI.`,
        });
      }

      return createVerifyJwt(createRemoteJWKSet(new URL(jwksUri), remoteJwkSet), jwtVerify)(token);
    };

  validateJwtIssuer = (issuer: string) => {
    const authServer = this.getAuthServerMetadataByIssuer(issuer);

    if (!authServer) {
      throw new MCPAuthBearerAuthError('invalid_issuer', {
        expected: this.authServers.map(({ metadata }) => metadata.issuer).join(', '),
        actual: issuer,
      });
    }
  };

  private getUnverifiedJwtIssuer(token: string): string {
    const payload = decodeJwt(token);
    if (!payload.iss) {
      throw new MCPAuthBearerAuthError('invalid_token', {
        cause: 'The JWT payload does not contain the `iss` field or it is malformed.',
      });
    }

    return payload.iss;
  }

  private getAuthServerMetadataByIssuer(issuer: string) {
    return this.authServers.find(({ metadata }) => metadata.issuer === issuer)?.metadata;
  }
}
