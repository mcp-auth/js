/**
 * Default fallback paths defined by MCP 2025-03-26 (except for revocation).
 *
 * @see [Fallbacks for Servers without Metadata Discovery](https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization#2-3-3-fallbacks-for-servers-without-metadata-discovery)
 */
export const defaultPaths = Object.freeze({
  authorizationPath: '/authorize',
  tokenPath: '/token',
  registrationPath: '/register',
  /**
   * @remark This is defined by the MCP SDK, but not in the MCP spec.
   */
  revocationPath: '/revoke',
});
