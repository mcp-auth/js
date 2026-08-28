import { createRemoteJWKSet, type JWTVerifyGetKey } from 'jose';

import { MCPAuthAuthServerError } from './errors.js';
import { fetchServerConfig } from './fetch-server-config.js';
import { getIssuer, type AuthServerConfig, type AuthServerMetadata } from './types.js';
import { validateResolvedMetadata } from './validate-auth-server.js';

/**
 * Holds the runtime state for the single authorization server trusted by an `MCPAuth` instance:
 * the (possibly lazily discovered) server metadata and the remote JWK Set.
 *
 * - For resolved configs (with metadata), the metadata is returned directly; it has already been
 *   validated by the `MCPAuth` constructor.
 * - For discovery configs (issuer + type), the metadata is fetched on first use and validated
 *   when it resolves. The in-flight promise is cached so concurrent calls share a single fetch,
 *   and the cache is reset on failure so a transient discovery error does not stick.
 * - The remote JWK Set instance is created once and reused, so jose's internal caching
 *   (`cooldownDuration`, `cacheMaxAge`) works effectively across requests.
 */
export class AuthServerContext {
  #metadata?: Promise<AuthServerMetadata>;
  #jwks?: JWTVerifyGetKey;

  constructor(private readonly config: AuthServerConfig) {}

  /**
   * The issuer identifier of the trusted authorization server, available without fetching the
   * metadata. Used to reject tokens from unknown issuers before any network request.
   */
  get issuer(): string {
    return getIssuer(this.config);
  }

  async getMetadata(): Promise<AuthServerMetadata> {
    if ('metadata' in this.config) {
      return this.config.metadata;
    }

    this.#metadata ??= this.#fetchMetadata(this.config.issuer, this.config.type);

    try {
      return await this.#metadata;
    } catch (error) {
      // Reset the cache so a transient discovery failure does not stick.
      this.#metadata = undefined;
      throw error;
    }
  }

  async getJwks(): Promise<JWTVerifyGetKey> {
    const { jwks_uri: jwksUri } = await this.getMetadata();

    if (!jwksUri) {
      throw new MCPAuthAuthServerError('missing_jwks_uri', {
        cause: `The authorization server (\`${this.issuer}\`) does not have a JWKS URI configured.`,
      });
    }

    this.#jwks ??= createRemoteJWKSet(new URL(jwksUri));
    return this.#jwks;
  }

  async #fetchMetadata(
    issuer: string,
    type: AuthServerConfig['type']
  ): Promise<AuthServerMetadata> {
    const { metadata } = await fetchServerConfig(issuer, { type });
    validateResolvedMetadata(metadata);
    return metadata;
  }
}
