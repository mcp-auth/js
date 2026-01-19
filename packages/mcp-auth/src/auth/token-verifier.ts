import { trySafe } from '@silverhand/essentials';
import {
  createRemoteJWKSet,
  decodeJwt,
  type JWTVerifyOptions,
  type RemoteJWKSetOptions,
} from 'jose';

import { MCPAuthAuthServerError, MCPAuthBearerAuthError } from '../errors.js';
import {
  type ValidateIssuerFunction,
  type VerifyAccessTokenFunction,
} from '../handlers/handle-bearer-auth.js';
import { type AuthServerConfig, getIssuer } from '../types/auth-server.js';
import { createVerifyJwt } from '../utils/create-verify-jwt.js';

import { AuthServerMetadataCache } from './auth-server-metadata-cache.js';

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

export type GetTokenVerifierOptions = {
  resource: string;
};

/**
 * Encapsulates all authentication logic and policies for a specific protected resource
 * or a legacy `server` configuration.
 *
 * This class is a central internal abstraction that holds the authentication context, such as
 * the complete list of trusted authorization servers. It is responsible for creating
 * verification functions and validating token issuers based on that context.
 *
 * Supports both resolved configs (with metadata) and discovery configs (with on-demand
 * metadata fetching), making it compatible with edge runtimes like Cloudflare Workers.
 */
export class TokenVerifier {
  /**
   * Cache for remote JWK Set instances, keyed by JWKS URI.
   * This ensures we reuse the same instance for the same URI, allowing jose's
   * internal caching (cooldownDuration, cacheMaxAge) to work effectively.
   */
  private readonly jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

  /**
   * Cache for auth server metadata, supporting both resolved and discovery configs.
   */
  private readonly metadataCache = new AuthServerMetadataCache();

  /**
   * Creates an instance of TokenVerifier.
   * @param authServers The complete configuration of all authorization servers trusted by the
   * associated resource. Can include both resolved configs (with metadata) and discovery configs
   * (with just issuer and type).
   */
  constructor(private readonly authServers: AuthServerConfig[]) {}

  /**
   * A factory method that creates a JWT verification function tailored to this verifier's policies.
   * The returned function will only trust issuers specified in this verifier's `authServers`.
   *
   * For discovery configs, the metadata will be fetched on first token verification.
   *
   * @param config The per-call configuration for JWT verification.
   * @returns A function that takes a token string and returns a promise resolving with the
   * verified claims.
   */
  createVerifyJwtFunction({ jwtVerify, remoteJwkSet }: VerifyJwtConfig): VerifyAccessTokenFunction {
    return async (token: string) => {
      const unverifiedIssuer = this.getUnverifiedJwtIssuer(token);
      /**
       * This is a pre-check step before the actual verification of the JWT.
       * It validates the issuer against this verifier's trusted list *before* attempting
       * to fetch the JWKS, ensuring we only interact with expected servers.
       */
      this.getJwtIssuerValidator()(unverifiedIssuer);

      const authServerConfig = this.getAuthServerConfigByIssuer(unverifiedIssuer);

      if (!authServerConfig) {
        // This shouldn't happen as getJwtIssuerValidator would have thrown
        throw new MCPAuthBearerAuthError('invalid_issuer', {
          expected: this.getTrustedIssuers().join(', '),
          actual: unverifiedIssuer,
        });
      }

      const metadata = await this.metadataCache.getMetadata(authServerConfig);

      if (!metadata.jwksUri) {
        throw new MCPAuthAuthServerError('missing_jwks_uri', {
          cause: `The authorization server (\`${unverifiedIssuer}\`) does not have a JWKS URI configured.`,
        });
      }

      const getKey = this.getOrCreateRemoteJWKSet(metadata.jwksUri, remoteJwkSet);
      return createVerifyJwt(getKey, jwtVerify)(token);
    };
  }

  /**
   * A factory method that creates an issuer validation function tailored to this verifier's policies.
   * The returned function will validate a given issuer against the list of trusted authorization
   * servers, providing precise error messages on failure.
   */
  getJwtIssuerValidator(): ValidateIssuerFunction {
    return (issuer: string) => {
      const authServerConfig = this.getAuthServerConfigByIssuer(issuer);

      if (!authServerConfig) {
        throw new MCPAuthBearerAuthError('invalid_issuer', {
          expected: this.getTrustedIssuers().join(', '),
          actual: issuer,
        });
      }
    };
  }

  /**
   * Gets the list of trusted issuer URLs from both resolved and discovery configs.
   */
  private getTrustedIssuers(): string[] {
    return this.authServers.map((config) => getIssuer(config));
  }

  /**
   * Finds the auth server config for a given issuer.
   * Works with both resolved configs (checks metadata.issuer) and discovery configs (checks issuer directly).
   */
  private getAuthServerConfigByIssuer(issuer: string): AuthServerConfig | undefined {
    return this.authServers.find((config) => getIssuer(config) === issuer);
  }

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
   * Gets an existing remote JWK Set instance from the cache, or creates a new one if not cached.
   * Caching the instance allows jose's internal mechanisms (cooldownDuration, cacheMaxAge) to
   * work effectively, reducing redundant HTTP requests to the JWKS endpoint.
   */
  private getOrCreateRemoteJWKSet(
    jwksUri: string,
    options?: RemoteJWKSetOptions
  ): ReturnType<typeof createRemoteJWKSet> {
    const cached = this.jwksCache.get(jwksUri);
    if (cached) {
      return cached;
    }

    const getKey = createRemoteJWKSet(new URL(jwksUri), options);
    this.jwksCache.set(jwksUri, getKey);
    return getKey;
  }
}
