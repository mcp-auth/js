import { trySafe } from '@silverhand/essentials';

const resourceMetadataBasePath = '/.well-known/oauth-protected-resource';

/**
 * Constructs the correct protected resource metadata URL from a resource identifier URI.
 *
 * This utility implements the path construction logic from RFC 9728, Section 3.1.
 * It correctly handles resource identifiers with and without path components by inserting
 * the well-known path segment between the host and the resource's path.
 *
 * @example
 * // For 'https://api.example.com' -> '.../.well-known/oauth-protected-resource'
 * // For 'https://api.example.com/billing' -> '.../.well-known/oauth-protected-resource/billing'
 *
 * @param resource The resource identifier URI string.
 * @returns A URL object representing the full metadata endpoint.
 */
export const createResourceMetadataEndpoint = (resource: string) => {
  const resourceUrl = trySafe(() => new URL(resource));
  if (!resourceUrl) {
    throw new TypeError(`Invalid resource identifier URI: ${resource}`);
  }

  // If the resource has no path (or is just '/'), the endpoint is at the base.
  if (resourceUrl.pathname === '/') {
    return new URL(resourceMetadataBasePath, resourceUrl.origin);
  }

  // Otherwise, append the resource's path to the base well-known path.
  return new URL(`${resourceMetadataBasePath}${resourceUrl.pathname}`, resourceUrl.origin);
};
