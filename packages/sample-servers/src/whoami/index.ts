/**
 * The WhoAmI MCP server, built as a Cloudflare Worker with Hono.
 *
 * It demonstrates the minimal mcp-auth wiring: verify JWT access tokens with `MCPAuth`, serve
 * the OAuth discovery documents, and read the verified identity in a tool with `getAuthInfo`.
 *
 * @see {@link file://./server.ts} for the MCP server definition (tools).
 * @see {@link file://./auth.ts} for the auth wiring (verifier + middlewares).
 * @see {@link https://mcp-auth.dev/docs/tutorials/whoami Tutorial} for the full tutorial.
 */

import { createMcpHandler } from '@modelcontextprotocol/server';
import { Hono } from 'hono';

import { bearerAuth, oauthDiscovery, type HonoEnv } from './auth.js';
import { createMcpServer } from './server.js';

const handler = createMcpHandler(createMcpServer);

const app = new Hono<HonoEnv>();

app.use('/.well-known/*', oauthDiscovery);
app.all('/', bearerAuth, async (context) =>
  handler.fetch(context.req.raw, { authInfo: context.get('authInfo') })
);

export default app;
