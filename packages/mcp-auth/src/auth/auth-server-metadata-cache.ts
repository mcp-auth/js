import { type AuthServerConfig } from '../types/auth-server.js';
import { type CamelCaseAuthorizationServerMetadata } from '../types/oauth.js';
import { fetchServerConfig } from '../utils/fetch-server-config.js';
import { validateResolvedAuthServer } from '../utils/validate-auth-server.js';

/**
 * A cache that stores auth server metadata with support for on-demand fetching.
 *
 * For resolved configs (with metadata), returns the metadata directly.
 * For discovery configs (issuer + type only), fetches metadata on first access and caches it.
 *
 * Uses a two-layer cache to prevent duplicate concurrent requests:
 * - `valueCache`: stores resolved metadata
 * - `promiseCache`: stores in-flight promises (removed after resolution)
 */
export class AuthServerMetadataCache {
  private readonly valueCache = new Map<string, CamelCaseAuthorizationServerMetadata>();
  private readonly promiseCache = new Map<string, Promise<CamelCaseAuthorizationServerMetadata>>();

  /**
   * Get metadata for the given auth server config.
   *
   * - Resolved config: returns metadata directly
   * - Discovery config: fetches metadata on first call, validates it, and returns cached value on subsequent calls
   *
   * Concurrent calls for the same issuer will share a single fetch request.
   */
  async getMetadata(config: AuthServerConfig): Promise<CamelCaseAuthorizationServerMetadata> {
    if ('metadata' in config) {
      return config.metadata;
    }

    const { issuer, type } = config;

    // Return cached value if exists
    const cached = this.valueCache.get(issuer);
    if (cached) {
      return cached;
    }

    // Return existing promise if request is in progress
    const existingPromise = this.promiseCache.get(issuer);
    if (existingPromise) {
      return existingPromise;
    }

    // Create new promise
    const promise = (async () => {
      try {
        const resolvedConfig = await fetchServerConfig(issuer, { type });
        // Validate the fetched metadata
        validateResolvedAuthServer(resolvedConfig);
        this.valueCache.set(issuer, resolvedConfig.metadata);
        return resolvedConfig.metadata;
      } finally {
        this.promiseCache.delete(issuer);
      }
    })();

    this.promiseCache.set(issuer, promise);
    return promise;
  }
}
