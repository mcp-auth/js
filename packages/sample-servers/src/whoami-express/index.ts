/**
 * The WhoAmI MCP server on Node.js with Express.
 *
 * The MCP server definition is runtime-agnostic, so this sample reuses `server.ts` from the
 * Cloudflare Workers sample verbatim — only the wiring changes: the Express middlewares come
 * from `@modelcontextprotocol/express`, and `toNodeHandler` adapts the same web-standard MCP
 * handler to Node's request/response model (forwarding `req.auth` as the handler's auth info).
 */

import {
  createMcpExpressApp,
  mcpAuthMetadataRouter,
  requireBearerAuth,
} from '@modelcontextprotocol/express';
import { toNodeHandler } from '@modelcontextprotocol/node';
import { createMcpHandler } from '@modelcontextprotocol/server';
import { MCPAuth } from 'mcp-auth';

import { createMcpServer } from '../whoami/server.js';

const { MCP_AUTH_ISSUER, MCP_RESOURCE_IDENTIFIER } = process.env;

if (!MCP_AUTH_ISSUER) {
  throw new Error('MCP_AUTH_ISSUER environment variable is required');
}

if (!MCP_RESOURCE_IDENTIFIER) {
  throw new Error('MCP_RESOURCE_IDENTIFIER environment variable is required');
}

const mcpAuth = new MCPAuth({
  protectedResourceMetadata: {
    resource: MCP_RESOURCE_IDENTIFIER,
    authorizationServer: { issuer: MCP_AUTH_ISSUER, type: 'oidc' },
  },
});

const mcpNodeHandler = toNodeHandler(createMcpHandler(createMcpServer));

const PORT = 3001;
const app = createMcpExpressApp();

// Serve the OAuth discovery documents (`/.well-known/...`)
app.use(mcpAuthMetadataRouter(await mcpAuth.getAuthMetadataOptions()));

app.all(
  '/',
  // Require a valid Bearer token; the verified auth info flows to the handler via `req.auth`
  requireBearerAuth(mcpAuth.getBearerAuthOptions()),
  /*
   * `createMcpExpressApp` applies `express.json()`, which drains the request stream, so the
   * parsed body is passed along explicitly.
   */
  async (request, response) => mcpNodeHandler(request, response, request.body)
);

app.listen(PORT);
