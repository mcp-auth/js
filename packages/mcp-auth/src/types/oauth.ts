import camelcaseKeys from 'camelcase-keys';
import { z } from 'zod';

/**
 * Zod schema for OAuth 2.0 Authorization Server Metadata as defined in RFC 8414. This schema is
 * not intended to be used directly for validation, but rather as a reference for the actual
 * zod schemata that will be used in the application.
 */
const authorizationServerMetadataObject = Object.freeze({
  /**
   * The authorization server's issuer identifier, which is a URL that uses the `https` scheme and
   * has no query or fragment components.
   */
  issuer: z.string(),
  /**
   * URL of the authorization server's authorization endpoint [[RFC6749](https://rfc-editor.org/rfc/rfc6749)].
   * This is REQUIRED unless no grant types are supported that use the authorization endpoint.
   *
   * @see https://rfc-editor.org/rfc/rfc6749#section-3.1
   */
  authorization_endpoint: z.string(),
  /**
   * URL of the authorization server's token endpoint [[RFC6749](https://rfc-editor.org/rfc/rfc6749)].
   * This is REQUIRED unless only the implicit grant type is supported.
   *
   * @see https://rfc-editor.org/rfc/rfc6749#section-3.2
   */
  token_endpoint: z.string(),
  /**
   * URL of the authorization server's JWK Set [[JWK](https://www.rfc-editor.org/rfc/rfc8414.html#ref-JWK)]
   * document. The referenced document contains the signing key(s) the client uses to validate
   * signatures from the authorization server. This URL MUST use the `https` scheme.
   */
  jwks_uri: z.string().optional(),
  /**
   * URL of the authorization server's OAuth 2.0 Dynamic Client Registration endpoint
   * [[RFC7591](https://www.rfc-editor.org/rfc/rfc7591)].
   */
  registration_endpoint: z.string().optional(),
  scope_supported: z.array(z.string()).optional(),
  /**
   * JSON array containing a list of the OAuth 2.0 `response_type` values that this authorization
   * server supports. The array values used are the same as those used with the `response_types`
   * parameter defined by "OAuth 2.0 Dynamic Client Registration Protocol"
   * [[RFC7591](https://www.rfc-editor.org/rfc/rfc7591)].
   */
  response_types_supported: z.array(z.string()),
  /**
   * JSON array containing a list of the OAuth 2.0 `response_mode` values that this
   * authorization server supports, as specified in "OAuth 2.0 Multiple Response
   * Type Encoding Practices"
   * [[OAuth.Responses](https://datatracker.ietf.org/doc/html/rfc8414#ref-OAuth.Responses)].
   *
   * If omitted, the default is `["query", "fragment"]`. The response mode value `"form_post"` is
   * also defined in "OAuth 2.0 Form Post Response Mode"
   * [[OAuth.FormPost](https://datatracker.ietf.org/doc/html/rfc8414#ref-OAuth.Post)].
   */
  response_modes_supported: z.array(z.string()).optional(),
  /**
   * JSON array containing a list of the OAuth 2.0 grant type values that this authorization server
   * supports. The array values used are the same as those used with the `grant_types` parameter
   * defined by "OAuth 2.0 Dynamic Client Registration Protocol" [[RFC7591](https://www.rfc-editor.org/rfc/rfc7591)].
   * If omitted, the default value is `["authorization_code", "implicit"]`.
   */
  grant_types_supported: z.array(z.string()).optional(),
  token_endpoint_auth_methods_supported: z.array(z.string()).optional(),
  token_endpoint_auth_signing_alg_values_supported: z.array(z.string()).optional(),
  service_documentation: z.string().optional(),
  ui_locales_supported: z.array(z.string()).optional(),
  op_policy_uri: z.string().optional(),
  op_tos_uri: z.string().optional(),
  /**
   * URL of the authorization server's OAuth 2.0 revocation endpoint
   * [[RFC7009](https://www.rfc-editor.org/rfc/rfc7009)].
   */
  revocation_endpoint: z.string().optional(),
  revocation_endpoint_auth_methods_supported: z.array(z.string()).optional(),
  revocation_endpoint_auth_signing_alg_values_supported: z.array(z.string()).optional(),
  /**
   * URL of the authorization server's OAuth 2.0 introspection endpoint
   * [[RFC7662](https://www.rfc-editor.org/rfc/rfc7662)].
   */
  introspection_endpoint: z.string().optional(),
  introspection_endpoint_auth_methods_supported: z.array(z.string()).optional(),
  introspection_endpoint_auth_signing_alg_values_supported: z.array(z.string()).optional(),
  /**
   * JSON array containing a list of Proof Key for Code Exchange (PKCE)
   * [[RFC7636](https://www.rfc-editor.org/rfc/rfc7636)] code challenge methods supported by this
   * authorization server.
   */
  code_challenge_methods_supported: z.array(z.string()).optional(),
  /**
   * URL of the OpenID Connect [userinfo endpoint](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo).
   * This endpoint is used to retrieve information about the authenticated user.
   */
  userinfo_endpoint: z.string().optional(),
});

/**
 * Zod schema for OAuth 2.0 Authorization Server Metadata as defined in RFC 8414.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8414
 */
export const authorizationServerMetadataSchema = z.object(authorizationServerMetadataObject);

/**
 * Schema for OAuth 2.0 Authorization Server Metadata as defined in RFC 8414.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8414
 */
export type AuthorizationServerMetadata = z.infer<typeof authorizationServerMetadataSchema>;

/**
 * The camelCase version of the OAuth 2.0 Authorization Server Metadata Zod schema.
 *
 * @see {@link authorizationServerMetadataSchema} for the original schema and field information.
 */
export const camelCaseAuthorizationServerMetadataSchema = z.object(
  camelcaseKeys(authorizationServerMetadataObject)
);

/**
 * The camelCase version of the OAuth 2.0 Authorization Server Metadata type.
 *
 * @see {@link AuthorizationServerMetadata} for the original type and field information.
 */
export type CamelCaseAuthorizationServerMetadata = z.infer<
  typeof camelCaseAuthorizationServerMetadataSchema
>;

export const defaultValues: Readonly<Partial<CamelCaseAuthorizationServerMetadata>> = Object.freeze(
  {
    grantTypesSupported: ['authorization_code', 'implicit'],
    responseModesSupported: ['query', 'fragment'],
  }
);

/**
 * Zod schema for OAuth 2.0 Protected Resource Metadata. This schema is
 * not intended to be used directly for validation, but rather as a reference for the actual
 * zod schemata that will be used in the application.
 */
const protectedResourceMetadataObject = Object.freeze({
  /**
   * The protected resource's resource identifier.
   */
  resource: z.string(),
  /**
   * List of OAuth authorization server issuer identifiers that can be used with this protected resource.
   */
  authorization_servers: z.array(z.string()).optional(),
  /**
   * URL of the protected resource's JSON Web Key (JWK) Set document containing public keys for signature verification.
   */
  jwks_uri: z.string().optional(),
  /**
   * List of scope values used in authorization requests to access this protected resource.
   */
  scopes_supported: z.array(z.string()).optional(),
  /**
   * Supported methods for sending OAuth 2.0 bearer tokens. Values: ["header", "body", "query"].
   */
  bearer_methods_supported: z.array(z.string()).optional(),
  /**
   * JWS signing algorithms supported by the protected resource for signing resource responses.
   */
  resource_signing_alg_values_supported: z.array(z.string()).optional(),
  /**
   * Human-readable name of the protected resource for display to end users.
   */
  resource_name: z.string().optional(),
  /**
   * URL containing developer documentation for using the protected resource.
   */
  resource_documentation: z.string().optional(),
  /**
   * URL containing information about the protected resource's data usage requirements.
   */
  resource_policy_uri: z.string().optional(),
  /**
   * URL containing the protected resource's terms of service.
   */
  resource_tos_uri: z.string().optional(),
  /**
   * Whether the protected resource supports mutual-TLS client certificate-bound access tokens.
   */
  tls_client_certificate_bound_access_tokens: z.boolean().optional(),
  /**
   * Authorization details type values supported when using the authorization_details request parameter.
   */
  authorization_details_types_supported: z.array(z.string()).optional(),
  /**
   * JWS algorithms supported for validating DPoP proof JWTs.
   */
  dpop_signing_alg_values_supported: z.array(z.string()).optional(),
  /**
   * Whether the protected resource always requires DPoP-bound access tokens.
   */
  dpop_bound_access_tokens_required: z.boolean().optional(),
  /**
   * A signed JWT containing metadata parameters as claims. The JWT must be signed using JWS and include
   * an 'iss' claim. Values in signed metadata take precedence over plain JSON values.
   */
  signed_metadata: z.string().optional(),
});

/**
 * Zod schema for OAuth 2.0 Protected Resource Metadata.
 */
export const protectedResourceMetadataSchema = z.object(protectedResourceMetadataObject);

/**
 * Schema for OAuth 2.0 Protected Resource Metadata.
 */
export type ProtectedResourceMetadata = z.infer<typeof protectedResourceMetadataSchema>;

/**
 * The camelCase version of the OAuth 2.0 Protected Resource Metadata Zod schema.
 *
 * @see {@link protectedResourceMetadataSchema} for the original schema and field information.
 */
export const camelCaseProtectedResourceMetadataSchema = z.object(
  camelcaseKeys(protectedResourceMetadataObject)
);

/**
 * The camelCase version of the OAuth 2.0 Protected Resource Metadata type.
 *
 * @see {@link ProtectedResourceMetadata} for the original type and field information.
 */
export type CamelCaseProtectedResourceMetadata = z.infer<
  typeof camelCaseProtectedResourceMetadataSchema
>;
