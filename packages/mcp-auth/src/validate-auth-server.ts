import { MCPAuthAuthServerError } from './errors.js';
import { type AuthServerMetadata } from './types.js';

/*
 * Default values defined by RFC 8414 for metadata fields that may be omitted.
 * @see https://datatracker.ietf.org/doc/html/rfc8414#section-2
 */
const defaultGrantTypesSupported = Object.freeze(['authorization_code', 'implicit']);

const isNonEmptyString = (value: unknown): value is string =>
  typeof value === 'string' && value.length > 0;

const isStringArray = (value: unknown): value is string[] =>
  Array.isArray(value) && value.every((item) => typeof item === 'string');

const isOptional =
  (check: (value: unknown) => boolean) =>
  (value: unknown): boolean =>
    value === undefined || check(value);

/*
 * The structural requirements for authorization server metadata. Only the fields that mcp-auth
 * consumes (plus the fields RFC 8414 marks as required) are checked; everything else is passed
 * through verbatim.
 */
const metadataFieldChecks: Readonly<Record<string, (value: unknown) => boolean>> = Object.freeze({
  issuer: isNonEmptyString,
  authorization_endpoint: isNonEmptyString,
  token_endpoint: isNonEmptyString,
  response_types_supported: isStringArray,
  jwks_uri: isOptional(isNonEmptyString),
  registration_endpoint: isOptional(isNonEmptyString),
  scopes_supported: isOptional(isStringArray),
  grant_types_supported: isOptional(isStringArray),
  code_challenge_methods_supported: isOptional(isStringArray),
});

/**
 * Validates the structure of raw authorization server metadata and returns it typed as
 * {@link AuthServerMetadata}.
 *
 * @param data The raw metadata object, e.g. the JSON response from a discovery endpoint.
 * @returns The validated metadata in wire format (snake_case).
 * @throws {MCPAuthAuthServerError} with code `'invalid_server_metadata'` if the metadata is not
 * an object or a checked field has an unexpected type.
 */
export const parseAuthServerMetadata = (data: unknown): AuthServerMetadata => {
  if (typeof data !== 'object' || data === null || Array.isArray(data)) {
    throw new MCPAuthAuthServerError('invalid_server_metadata', {
      metadata: data,
      message: 'The server metadata is not a valid object or is null.',
    });
  }

  const record: Record<string, unknown> = { ...data };
  const invalidFields = Object.entries(metadataFieldChecks)
    .filter(([field, check]) => !check(record[field]))
    .map(([field]) => field);

  if (invalidFields.length > 0) {
    throw new MCPAuthAuthServerError('invalid_server_metadata', {
      metadata: data,
      message: `The server metadata has missing or malformed fields: ${invalidFields.join(', ')}.`,
    });
  }

  /*
   * The checks above guarantee the required fields of `AuthServerMetadata`; the remaining
   * (optional) fields are passed through verbatim under the loose index signature.
   */
  // eslint-disable-next-line no-restricted-syntax
  return data as AuthServerMetadata;
};

export type AuthServerValidationResult = {
  /** Human-readable descriptions of the MCP specification violations found in the metadata. */
  errors: string[];
  /** Human-readable descriptions of non-fatal issues found in the metadata. */
  warnings: string[];
};

/**
 * Checks the authorization server metadata against the requirements of the MCP authorization
 * specification (authorization code grant with PKCE `S256`).
 *
 * @param metadata The structurally valid metadata to check.
 * @returns The errors and warnings found. An empty `errors` array means the server is usable.
 */
export const validateAuthServerMetadata = (
  metadata: AuthServerMetadata
): AuthServerValidationResult => {
  const errors: string[] = [];
  const warnings: string[] = [];

  /* eslint-disable @silverhand/fp/no-mutating-methods -- for the sake of readability */
  if (!metadata.response_types_supported.some((type) => type.split(' ').includes('code'))) {
    errors.push(
      'The server does not support the `code` response type, which is required for the authorization code flow.'
    );
  }

  if (
    !(metadata.grant_types_supported ?? defaultGrantTypesSupported).includes('authorization_code')
  ) {
    errors.push('The server does not support the `authorization_code` grant type.');
  }

  if (metadata.code_challenge_methods_supported) {
    if (!metadata.code_challenge_methods_supported.includes('S256')) {
      errors.push(
        'The server does not support the `S256` code challenge method for Proof Key for Code Exchange (PKCE).'
      );
    }
  } else {
    errors.push('The server does not support Proof Key for Code Exchange (PKCE).');
  }

  if (!metadata.registration_endpoint) {
    warnings.push('Dynamic Client Registration (RFC 7591) is not supported by the server.');
  }
  /* eslint-enable @silverhand/fp/no-mutating-methods */

  return { errors, warnings };
};

/**
 * Validates resolved authorization server metadata against the MCP specification, logging
 * warnings and throwing on errors.
 *
 * @param metadata The structurally valid metadata to validate.
 * @throws {MCPAuthAuthServerError} with code `'invalid_server_config'` if the metadata violates
 * the MCP authorization specification.
 */
export const validateResolvedMetadata = (metadata: AuthServerMetadata) => {
  const { errors, warnings } = validateAuthServerMetadata(metadata);

  if (errors.length > 0) {
    throw new MCPAuthAuthServerError('invalid_server_config', { errors, warnings });
  }

  if (warnings.length > 0) {
    console.warn(
      `The authorization server (issuer: \`${metadata.issuer}\`) configuration has warnings:\n\n  - ${warnings.join('\n  - ')}\n`
    );
  }
};
