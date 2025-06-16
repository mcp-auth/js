import { trySafe } from '@silverhand/essentials';
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
 * Defines configuration options for creating a JWT verification function.
 */
export type VerifyJwtConfig = {
  /**
   * Per-call options passed to the underlying `jose.jwtVerify` function.
   * @see {@link JWTVerifyOptions}
   */
  jwtVerify?: JWTVerifyOptions;
  /**
   * Per-call options passed to the underlying `jose.createRemoteJWKSet` function.
   * @see {@link RemoteJWKSetOptions}
   */
  remoteJwkSet?: RemoteJWKSetOptions;
};

/**
 * Encapsulates all authentication logic and policies for a specific protected resource
 * or a legacy `server` configuration.
 *
 * This class is a central internal abstraction that holds the authentication context, such as
 * the complete list of trusted authorization servers. It is responsible for creating
 * verification functions and validating token issuers based on that context.
 */
export class TokenVerifier {
  /**
   * Creates an instance of TokenVerifier.
   * @param authServers The complete configuration of all authorization servers trusted by the
   * associated resource.
   */
  constructor(private readonly authServers: AuthServerConfig[]) {}

  /**
   * A factory method that creates a JWT verification function tailored to this verifier's policies.
   * The returned function will only trust issuers specified in this verifier's `authServers`.
   * @param config The per-call configuration for JWT verification.
   * @returns A function that takes a token string and returns a promise resolving with the
   * verified claims.
   */
  createVerifyJwtFunction =
    ({ jwtVerify, remoteJwkSet }: VerifyJwtConfig) =>
    async (token: string) => {
      const unverifiedIssuer = this.getUnverifiedJwtIssuer(token);
      /**
       * This is a pre-check step before the actual verification of the JWT.
       * It validates the issuer against this verifier's trusted list *before* attempting
       * to fetch the JWKS, ensuring we only interact with expected servers.
       */
      this.validateJwtIssuer(unverifiedIssuer);

      const { jwksUri } = this.getAuthServerMetadataByIssuer(unverifiedIssuer) ?? {};

      if (!jwksUri) {
        throw new MCPAuthAuthServerError('missing_jwks_uri', {
          cause: `The authorization server (\`${unverifiedIssuer}\`) does not have a JWKS URI configured.`,
        });
      }

      return createVerifyJwt(createRemoteJWKSet(new URL(jwksUri), remoteJwkSet), jwtVerify)(token);
    };

  /**
   * Validates that a given issuer is in the list of trusted authorization servers for this resource.
   * This method provides precise error messages, listing all expected issuers on failure.
   * @param issuer The issuer string to validate.
   */
  validateJwtIssuer = (issuer: string) => {
    const authServer = this.getAuthServerMetadataByIssuer(issuer);

    if (!authServer) {
      throw new MCPAuthBearerAuthError('invalid_issuer', {
        expected: this.authServers.map(({ metadata }) => metadata.issuer).join(', '),
        actual: issuer,
      });
    }
  };

  /**
   * Decodes a JWT to extract its issuer without performing signature verification.
   * This is a necessary first step to determine which authorization server's keys to use.
   * @param token The raw JWT string.
   * @returns The issuer (`iss` claim) from the token payload.
   * @throws {@link MCPAuthBearerAuthError} if the JWT is malformed or invalid.
   */
  private getUnverifiedJwtIssuer(token: string): string {
    const payload = trySafe(() => decodeJwt(token));

    if (!payload) {
      throw new MCPAuthBearerAuthError('invalid_token', {
        cause: 'The JWT is malformed or invalid.',
      });
    }

    if (!payload.iss) {
      throw new MCPAuthBearerAuthError('invalid_token', {
        cause: 'The JWT payload does not contain the `iss` field.',
      });
    }

    return payload.iss;
  }

  /**
   * Finds the full metadata for a given issuer from the list of configured authorization servers.
   * @param issuer The issuer URL to look up.
   * @returns The corresponding `AuthServerMetadata` or `undefined` if not found.
   */
  private getAuthServerMetadataByIssuer(issuer: string) {
    return this.authServers.find(({ metadata }) => metadata.issuer === issuer)?.metadata;
  }
}
