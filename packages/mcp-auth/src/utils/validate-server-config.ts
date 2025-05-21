import { condObject } from '@silverhand/essentials';

import { type AuthServerConfig } from '../types/auth-server.js';
import { camelCaseAuthorizationServerMetadataSchema, defaultValues } from '../types/oauth.js';

/**
 * The codes for successful validation of the authorization server metadata.
 */
export type AuthServerSuccessCode =
  | 'server_metadata_valid'
  | 'dynamic_registration_supported'
  | 'pkce_supported'
  | 's256_code_challenge_method_supported'
  | 'authorization_code_grant_supported'
  | 'code_response_type_supported';

const authServerSuccessDescription: Readonly<Record<AuthServerSuccessCode, string>> = Object.freeze(
  {
    server_metadata_valid: 'The server metadata is valid and conforms to the expected schema.',
    dynamic_registration_supported:
      'Dynamic Client Registration (RFC 7591) is supported by the server.',
    pkce_supported: 'Proof Key for Code Exchange (PKCE) is supported by the server.',
    s256_code_challenge_method_supported:
      'The "S256" code challenge method for Proof Key for Code Exchange (PKCE) is supported by the server.',
    authorization_code_grant_supported:
      'The "authorization_code" grant type is supported by the server.',
    code_response_type_supported: 'The "code" response type is supported by the server.',
  }
);

type AuthServerSuccess = {
  /**
   * The code representing the specific success validation.
   */
  code: AuthServerSuccessCode;
  /**
   * A human-readable description of the success.
   */
  description: string;
};

const createSuccess = (code: AuthServerSuccessCode): AuthServerSuccess => ({
  code,
  description: authServerSuccessDescription[code],
});

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

type ValidateServerConfig = {
  /**
   * Validates the authorization server configuration against the MCP specification.
   *
   * @param config The configuration object containing the server metadata to validate.
   * @returns An object indicating whether the configuration is valid (`{ isValid: true }`) or
   * invalid (`{ isValid: false }`), along with any errors or warnings encountered during validation.
   * @see {@link AuthServerConfigValidationResult} for the structure of the return value.
   */
  (config: Readonly<AuthServerConfig>): AuthServerConfigValidationResult;
  /**
   * Validates the authorization server configuration against the MCP specification.
   *
   * @param config The configuration object containing the server metadata to validate.
   * @param verbose If `true`, the validation will include success messages in the result.
   * @returns An object indicating whether the configuration is valid (`{ isValid: true }`) or
   * invalid (`{ isValid: false }`), along with any errors or warnings encountered during validation.
   * @see {@link AuthServerConfigValidationResult} for the structure of the return value.
   */
  (
    config: Readonly<AuthServerConfig>,
    verbose: true
  ): AuthServerConfigValidationResult & {
    /** An array of success messages encountered during validation. */
    successes: AuthServerSuccess[];
  };
};

// eslint-disable-next-line complexity
export const validateServerConfig: ValidateServerConfig = (config, verbose = false) => {
  const { metadata } = config;
  const errors: AuthServerConfigError[] = [];
  const warnings: AuthServerConfigWarning[] = [];
  const successes: AuthServerSuccess[] = [];
  const parsed = camelCaseAuthorizationServerMetadataSchema.safeParse(metadata);
  const buildReturnValue = () =>
    // eslint-disable-next-line no-restricted-syntax -- the return type inference is beyond TypeScript's capabilities
    condObject({
      isValid: errors.length === 0,
      errors: errors.length > 0 ? errors : undefined,
      warnings,
      successes: verbose ? successes : undefined,
    }) as ReturnType<ValidateServerConfig>;

  /* eslint-disable @silverhand/fp/no-mutating-methods -- for the sake of readability */
  if (!parsed.success) {
    errors.push(createError('invalid_server_metadata', parsed.error));
    return buildReturnValue();
  }

  if (verbose) {
    successes.push(createSuccess('server_metadata_valid'));
  }

  if (!metadata.responseTypesSupported.some((type) => type.split(' ').includes('code'))) {
    errors.push(createError('code_response_type_not_supported'));
  } else if (verbose) {
    successes.push(createSuccess('code_response_type_supported'));
  }

  if (
    !(metadata.grantTypesSupported ?? defaultValues.grantTypesSupported)?.includes(
      'authorization_code'
    )
  ) {
    errors.push(createError('authorization_code_grant_not_supported'));
  } else if (verbose) {
    successes.push(createSuccess('authorization_code_grant_supported'));
  }

  if (metadata.codeChallengeMethodsSupported) {
    if (verbose) {
      successes.push(createSuccess('pkce_supported'));
    }
    if (!metadata.codeChallengeMethodsSupported.includes('S256')) {
      errors.push(createError('s256_code_challenge_method_not_supported'));
    } else if (verbose) {
      successes.push(createSuccess('s256_code_challenge_method_supported'));
    }
  } else {
    errors.push(createError('pkce_not_supported'));
  }

  if (!metadata.registrationEndpoint) {
    warnings.push(createWarning('dynamic_registration_not_supported'));
  } else if (verbose) {
    successes.push(createSuccess('dynamic_registration_supported'));
  }
  /* eslint-enable @silverhand/fp/no-mutating-methods */

  return buildReturnValue();
};
