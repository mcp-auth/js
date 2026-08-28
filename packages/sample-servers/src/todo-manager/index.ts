/**
 * The Todo Manager MCP server, built as a Cloudflare Worker with Hono.
 *
 * It demonstrates authorization with different permission scopes: per-tool required scopes via
 * `getAuthInfo`, and scope-dependent behavior combined with resource ownership.
 *
 * @see {@link file://./server.ts} for the MCP server definition (tools).
 * @see {@link file://./auth.ts} for the auth wiring (verifier + middlewares).
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
