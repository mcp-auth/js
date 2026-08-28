/**
 * The WhoAmI MCP server, built as a Cloudflare Worker.
 *
 * It demonstrates the minimal mcp-auth wiring: verify JWT access tokens with `MCPAuth`, serve
 * the OAuth discovery documents, and read the verified identity in a tool with `getAuthInfo`.
 *
 * @see {@link https://mcp-auth.dev/docs/tutorials/whoami Tutorial} for the full tutorial.
 */

import {
  createMcpHandler,
  McpServer,
  oauthMetadataResponse,
  requireBearerAuth,
} from '@modelcontextprotocol/server';
import { env } from 'cloudflare:workers';
import { getAuthInfo, MCPAuth } from 'mcp-auth';

// The factory creates a fresh MCP server instance per request, keeping requests isolated
const createMcpServer = () => {
  const mcpServer = new McpServer({
    name: 'WhoAmI',
    version: '0.0.0',
  });

  // Add a tool to the server that returns the current user's information
  mcpServer.registerTool(
    'whoami',
    {
      description: 'Get the current user information',
    },
    (context) => {
      const { claims } = getAuthInfo(context);
      return {
        content: [{ type: 'text', text: JSON.stringify(claims) }],
      };
    }
  );

  return mcpServer;
};

const handler = createMcpHandler(createMcpServer);

/*
 * Creating the MCPAuth instance performs no I/O, so it is safe at module scope. The
 * authorization server metadata is fetched lazily within request handling — Workers do not
 * allow network calls during module initialization.
 */
const mcpAuth = new MCPAuth({
  resource: env.MCP_RESOURCE_IDENTIFIER,
  authorizationServer: { issuer: env.MCP_AUTH_ISSUER, type: 'oidc' },
});

const gate = requireBearerAuth(mcpAuth.getBearerAuthOptions());

const worker = {
  async fetch(request: Request): Promise<Response> {
    /*
     * Serve the OAuth discovery documents. The path guard keeps the (lazily fetched) metadata
     * resolution off the request path of regular MCP traffic.
     */
    if (new URL(request.url).pathname.startsWith('/.well-known/')) {
      const metadataResponse = oauthMetadataResponse(
        request,
        await mcpAuth.getAuthMetadataOptions()
      );
      if (metadataResponse) {
        return metadataResponse;
      }
    }

    // Require a valid Bearer token, verified by the `MCPAuth` instance, for everything else
    const auth = await gate(request);
    if (auth instanceof Response) {
      return auth;
    }

    return handler.fetch(request, { authInfo: auth });
  },
};

export default worker;
