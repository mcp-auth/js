import { z } from 'zod';

/**
 * Schema for OAuth 2.0 Authorization Server Metadata as defined in RFC 8414.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8414
 */
export const authorizationServerMetadataSchemaGuard = z.object({
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
  authorizationEndpoint: z.string(),
  /**
   * URL of the authorization server's token endpoint [[RFC6749](https://rfc-editor.org/rfc/rfc6749)].
   * This is REQUIRED unless only the implicit grant type is supported.
   *
   * @see https://rfc-editor.org/rfc/rfc6749#section-3.2
   */
  tokenEndpoint: z.string(),
  /**
   * URL of the authorization server's JWK Set [[JWK](https://www.rfc-editor.org/rfc/rfc8414.html#ref-JWK)]
   * document. The referenced document contains the signing key(s) the client uses to validate
   * signatures from the authorization server. This URL MUST use the `https` scheme.
   */
  jwksUri: z.string().optional(),
  /**
   * URL of the authorization server's OAuth 2.0 Dynamic Client Registration endpoint
   * [[RFC7591](https://www.rfc-editor.org/rfc/rfc7591)].
   */
  registrationEndpoint: z.string().optional(),
  scopeSupported: z.array(z.string()).optional(),
  /**
   * JSON array containing a list of the OAuth 2.0 `response_type` values that this authorization
   * server supports. The array values used are the same as those used with the `response_types`
   * parameter defined by "OAuth 2.0 Dynamic Client Registration Protocol"
   * [[RFC7591](https://www.rfc-editor.org/rfc/rfc7591)].
   */
  responseTypesSupported: z.array(z.string()),
  responseModesSupported: z.array(z.string()).optional(),
  /**
   * JSON array containing a list of the OAuth 2.0 grant type values that this authorization server
   * supports. The array values used are the same as those used with the `grant_types` parameter
   * defined by "OAuth 2.0 Dynamic Client Registration Protocol" [[RFC7591](https://www.rfc-editor.org/rfc/rfc7591)].
   * If omitted, the default value is `["authorization_code", "implicit"]`.
   */
  grantTypesSupported: z.array(z.string()).optional(),
  tokenEndpointAuthMethodsSupported: z.array(z.string()).optional(),
  tokenEndpointAuthSigningAlgValuesSupported: z.array(z.string()).optional(),
  serviceDocumentation: z.string().optional(),
  uiLocalesSupported: z.array(z.string()).optional(),
  opPolicyUri: z.string().optional(),
  opTosUri: z.string().optional(),
  /**
   * URL of the authorization server's OAuth 2.0 revocation endpoint
   * [[RFC7009](https://www.rfc-editor.org/rfc/rfc7009)].
   */
  revocationEndpoint: z.string().optional(),
  revocationEndpointAuthMethodsSupported: z.array(z.string()).optional(),
  revocationEndpointAuthSigningAlgValuesSupported: z.array(z.string()).optional(),
  /**
   * URL of the authorization server's OAuth 2.0 introspection endpoint
   * [[RFC7662](https://www.rfc-editor.org/rfc/rfc7662)].
   */
  introspectionEndpoint: z.string().optional(),
  introspectionEndpointAuthMethodsSupported: z.array(z.string()).optional(),
  introspectionEndpointAuthSigningAlgValuesSupported: z.array(z.string()).optional(),
  /**
   * JSON array containing a list of Proof Key for Code Exchange (PKCE)
   * [[RFC7636](https://www.rfc-editor.org/rfc/rfc7636)] code challenge methods supported by this
   * authorization server.
   */
  codeChallengeMethodsSupported: z.array(z.string()).optional(),
});

/**
 * Schema for OAuth 2.0 Authorization Server Metadata
 * as defined in RFC 8414.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8414
 */
export type AuthorizationServerMetadata = z.infer<typeof authorizationServerMetadataSchemaGuard>;
