import { type AuthServerConfig } from '../types/auth-server.js';
import { camelCaseAuthorizationServerMetadataSchema } from '../types/oauth.js';

/**
 * The codes for errors that can occur when validating the authorization server metadata.
 */
export type AuthServerConfigErrorCode =
  | 'invalid_server_metadata'
  | 'code_response_type_not_supported'
  | 'authorization_code_grant_not_supported'
  | 'pkce_not_supported'
  | 's256_code_challenge_method_not_supported';

const authServerConfigErrorDescription: Readonly<Record<AuthServerConfigErrorCode, string>> =
  Object.freeze({
    invalid_server_metadata:
      'The server metadata is not a valid object or does not conform to the expected schema.',
    code_response_type_not_supported:
      'The server does not support the "code" response type or the "code" response type is not included in one of the supported response types.',
    authorization_code_grant_not_supported:
      'The server does not support the "authorization_code" grant type.',
    pkce_not_supported: 'The server does not support Proof Key for Code Exchange (PKCE).',
    s256_code_challenge_method_not_supported:
      'The server does not support the "S256" code challenge method for Proof Key for Code Exchange (PKCE).',
  });

/**
 * Represents an error that occurs during the validation of the authorization server metadata.
 */
export type AuthServerConfigError = {
  /**
   * The code representing the specific validation error.
   */
  code: AuthServerConfigErrorCode;
  /**
   * A human-readable description of the error.
   */
  description: string;
  /**
   * An optional cause of the error, typically an instance of `Error` that provides more context.
   */
  cause?: Error;
};

const createError = (code: AuthServerConfigErrorCode, cause?: Error): AuthServerConfigError => ({
  code,
  description: authServerConfigErrorDescription[code],
  cause,
});

/**
 * The codes for warnings that can occur when validating the authorization server metadata.
 */
export type AuthServerConfigWarningCode = 'dynamic_registration_not_supported';

const authServerConfigWarningDescription: Readonly<Record<AuthServerConfigWarningCode, string>> =
  Object.freeze({
    dynamic_registration_not_supported:
      'Dynamic Client Registration (RFC 7591) is not supported by the server.',
  });

/**
 * Represents a warning that occurs during the validation of the authorization server metadata.
 */
export type AuthServerConfigWarning = {
  /**
   * The code representing the specific validation warning.
   */
  code: AuthServerConfigWarningCode;
  /**
   * A human-readable description of the warning.
   */
  description: string;
};

const createWarning = (code: AuthServerConfigWarningCode): AuthServerConfigWarning => ({
  code,
  description: authServerConfigWarningDescription[code],
});

type AuthServerConfigValidationResult =
  | {
      /** Indicates that the server configuration is valid. Warnings may still be present. */
      isValid: true;
      /** An array of warnings encountered during validation. */
      warnings: AuthServerConfigWarning[];
    }
  | {
      /** Indicates that the server configuration is invalid. */
      isValid: false;
      /** An array of errors encountered during validation. */
      errors: AuthServerConfigError[];
      /** An array of warnings encountered during validation. */
      warnings: AuthServerConfigWarning[];
    };

/**
 * Validates the authorization server configuration against the MCP specification.
 *
 * @param param0 The configuration object containing the server metadata to validate.
 * @returns An object indicating whether the configuration is valid (`{ isValid: true }`) or
 * invalid (`{ isValid: false }`), along with any errors or warnings encountered during validation.
 * @see {@link AuthServerConfigValidationResult} for the structure of the return value.
 */
export const validateServerConfig = ({
  metadata,
}: Readonly<AuthServerConfig>): AuthServerConfigValidationResult => {
  const errors: AuthServerConfigError[] = [];
  const warnings: AuthServerConfigWarning[] = [];

  const parsed = camelCaseAuthorizationServerMetadataSchema.safeParse(metadata);

  /* eslint-disable @silverhand/fp/no-mutating-methods -- for the sake of readability */
  if (!parsed.success) {
    errors.push(createError('invalid_server_metadata', parsed.error));
    return { isValid: false, errors, warnings };
  }

  if (!metadata.responseTypesSupported.some((type) => type.split(' ').includes('code'))) {
    errors.push(createError('code_response_type_not_supported'));
  }

  if (!metadata.grantTypesSupported?.includes('authorization_code')) {
    errors.push(createError('authorization_code_grant_not_supported'));
  }

  if (!metadata.codeChallengeMethodsSupported) {
    errors.push(createError('pkce_not_supported'));
  } else if (!metadata.codeChallengeMethodsSupported.includes('S256')) {
    errors.push(createError('s256_code_challenge_method_not_supported'));
  }

  if (!metadata.registrationEndpoint) {
    warnings.push(createWarning('dynamic_registration_not_supported'));
  }
  /* eslint-enable @silverhand/fp/no-mutating-methods */

  return errors.length === 0 ? { isValid: true, warnings } : { isValid: false, errors, warnings };
};
