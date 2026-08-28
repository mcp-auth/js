import {
  oauthMetadataResponse,
  requireBearerAuth,
  type AuthInfo,
} from '@modelcontextprotocol/server';
import { env } from 'cloudflare:workers';
import { type MiddlewareHandler } from 'hono';
import { MCPAuth } from 'mcp-auth';

export type HonoEnv = { Variables: { authInfo: AuthInfo } };

/*
 * Creating the MCPAuth instance performs no I/O, so it is safe at module scope. The
 * authorization server metadata is fetched lazily within request handling — Workers do not
 * allow network calls during module initialization.
 */
const mcpAuth = new MCPAuth({
  protectedResourceMetadata: {
    resource: env.MCP_RESOURCE_IDENTIFIER,
    authorizationServer: { issuer: env.MCP_AUTH_ISSUER, type: 'oidc' },
    scopesSupported: ['create:todos', 'read:todos', 'delete:todos'],
  },
});

const gate = requireBearerAuth(mcpAuth.getBearerAuthOptions());

/**
 * Serves the OAuth discovery documents (RFC 9728 / RFC 8414), public by design.
 */
export const oauthDiscovery: MiddlewareHandler = async (context, next) => {
  const response = oauthMetadataResponse(context.req.raw, await mcpAuth.getAuthMetadataOptions());

  if (response) {
    return response;
  }

  await next();
};

/**
 * Verifies the Bearer token with the `MCPAuth` instance and exposes the auth info to
 * downstream handlers.
 */
export const bearerAuth: MiddlewareHandler<HonoEnv> = async (context, next) => {
  const authResult = await gate(context.req.raw);

  if (authResult instanceof Response) {
    return authResult;
  }

  context.set('authInfo', authResult);
  await next();
};
