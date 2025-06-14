import { MCPAuthAuthServerError } from '../errors.js';
import { type AuthServerConfig } from '../types/auth-server.js';

import { validateServerConfig } from './validate-server-config.js';

/**
 * Validates a single `AuthServerConfig` object and throws on error.
 * @param authServer The authorization server configuration to validate.
 */
export const validateAuthServer = (authServer: AuthServerConfig) => {
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
