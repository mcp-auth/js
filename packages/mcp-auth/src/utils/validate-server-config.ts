import { type AuthServerConfig } from '../types/auth-server.js';

export type AuthServerConfigErrorCode =
  | 'code_response_type_not_supported'
  | 'authorization_code_grant_not_supported'
  | 'pkce_not_supported'
  | 's256_code_challenge_method_not_supported';

export const authServerConfigErrorDescription: Readonly<Record<AuthServerConfigErrorCode, string>> =
  Object.freeze({
    code_response_type_not_supported:
      'The server does not support the "code" response type or the "code" response type is not included in one of the supported response types.',
    authorization_code_grant_not_supported:
      'The server does not support the "authorization_code" grant type.',
    pkce_not_supported: 'The server does not support Proof Key for Code Exchange (PKCE).',
    s256_code_challenge_method_not_supported:
      'The server does not support the "S256" code challenge method for Proof Key for Code Exchange (PKCE).',
  });

export type AuthServerConfigWarningCode = 'dynamic_registration_not_supported';

export const authServerConfigWarningDescription: Readonly<
  Record<AuthServerConfigWarningCode, string>
> = Object.freeze({
  dynamic_registration_not_supported:
    'Dynamic Client Registration (RFC 7591) is not supported by the server.',
});

type AuthServerConfigValidationResult =
  | {
      isValid: true;
      warnings: AuthServerConfigWarningCode[];
    }
  | {
      isValid: false;
      errors: AuthServerConfigErrorCode[];
      warnings: AuthServerConfigWarningCode[];
    };

export const validateServerConfig = ({
  metadata,
}: Readonly<AuthServerConfig>): AuthServerConfigValidationResult => {
  const errors: AuthServerConfigErrorCode[] = [];
  const warnings: AuthServerConfigWarningCode[] = [];

  /* eslint-disable @silverhand/fp/no-mutating-methods -- for the sake of readability */
  if (!metadata.responseTypesSupported.includes('code')) {
    errors.push('code_response_type_not_supported');
  }

  if (!metadata.grantTypesSupported?.includes('authorization_code')) {
    errors.push('authorization_code_grant_not_supported');
  }

  if (!metadata.codeChallengeMethodsSupported) {
    errors.push('pkce_not_supported');
  } else if (!metadata.codeChallengeMethodsSupported.includes('S256')) {
    errors.push('s256_code_challenge_method_not_supported');
  }

  if (!metadata.registrationEndpoint) {
    warnings.push('dynamic_registration_not_supported');
  }
  /* eslint-enable @silverhand/fp/no-mutating-methods */

  return errors.length === 0 ? { isValid: true, warnings } : { isValid: false, errors, warnings };
};
