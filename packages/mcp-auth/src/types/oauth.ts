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
