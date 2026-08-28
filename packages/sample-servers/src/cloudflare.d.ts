/*
 * Ambient types for the Cloudflare Workers runtime module and the bindings these samples use.
 * Projects generating types with `wrangler types` (or using `@cloudflare/workers-types`) get
 * these declarations generated instead.
 */
declare module 'cloudflare:workers' {
  export const env: {
    MCP_AUTH_ISSUER: string;
    MCP_RESOURCE_IDENTIFIER: string;
  };
}
