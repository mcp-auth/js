import { trySafe } from '@silverhand/essentials';

const resourceMetadataBasePath = '/.well-known/oauth-protected-resource';

export const createResourceMetadataEndpoint = (resource: string) => {
  const resourceUrl = trySafe(() => new URL(resource));
  if (!resourceUrl) {
    throw new TypeError(`Invalid resource: ${resource}`);
  }

  if (resourceUrl.pathname === '/') {
    return new URL(resourceMetadataBasePath, resourceUrl.origin);
  }

  return new URL(`${resourceMetadataBasePath}${resourceUrl.pathname}`, resourceUrl.origin);
};
