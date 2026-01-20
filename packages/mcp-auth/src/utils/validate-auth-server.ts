import { MCPAuthAuthServerError } from '../errors.js';
import { type AuthServerConfig, type ResolvedAuthServerConfig } from '../types/auth-server.js';

import { validateServerConfig } from './validate-server-config.js';

/**
 * Validates a resolved `AuthServerConfig` object and throws on error.
 *
 * @param authServer The resolved authorization server configuration to validate.
 */
export const validateResolvedAuthServer = (authServer: ResolvedAuthServerConfig) => {
  const result = validateServerConfig(authServer);

  if (!result.isValid) {
    throw new MCPAuthAuthServerError('invalid_server_config', {
      ...result,
    });
  }

  if (result.warnings.length > 0) {
    console.warn(
      `The authorization server (issuer: \`${authServer.metadata.issuer}\`) configuration has warnings:\n\n  - ${result.warnings.map(({ description }) => description).join('\n  - ')}\n`
    );
  }
};

/**
 * Validates an `AuthServerConfig` object and throws on error.
 *
 * For resolved configs (with metadata), performs full validation.
 * For discovery configs (without metadata), skips validation as metadata will be
 * validated when fetched on-demand.
 *
 * @param authServer The authorization server configuration to validate.
 */
export const validateAuthServer = (authServer: AuthServerConfig) => {
  // Skip validation for discovery configs - will be validated when metadata is fetched
  if (!('metadata' in authServer)) {
    return;
  }

  validateResolvedAuthServer(authServer);
};
