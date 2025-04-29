import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { configDotenv } from 'dotenv';
import express from 'express';
import { fetchServerConfig, MCPAuth } from 'mcp-auth';

import server from './mcp-server/index.js';

configDotenv();

const PORT = 3234;

const {
  MCP_AUTH_ISSUER,
  MCP_AUTH_TYPE = 'oidc', // Can be 'oauth' or 'oidc'
} = process.env;

if (!MCP_AUTH_ISSUER) {
  throw new Error('MCP_AUTH_ISSUER environment variable is required');
}

if (MCP_AUTH_TYPE !== 'oauth' && MCP_AUTH_TYPE !== 'oidc') {
  throw new Error('MCP_AUTH_TYPE must be either "oauth" or "oidc"');
}

const mcpAuth = new MCPAuth({
  server: await fetchServerConfig(MCP_AUTH_ISSUER, { type: MCP_AUTH_TYPE }),
});

const app = express();

app.use(mcpAuth.delegatedRouter());

const transports: Record<SSEServerTransport['sessionId'], SSEServerTransport> = {};

app.get('/sse', mcpAuth.bearerAuth('jwt'), async (_, response) => {
  const transport = new SSEServerTransport('/messages', response);
  // eslint-disable-next-line @silverhand/fp/no-mutation
  transports[transport.sessionId] = transport;
  response.on('close', () => {
    // eslint-disable-next-line @silverhand/fp/no-delete, @typescript-eslint/no-dynamic-delete
    delete transports[transport.sessionId];
  });
  await server.connect(transport);
});

app.post('/messages', mcpAuth.bearerAuth('jwt'), async (request, response) => {
  // eslint-disable-next-line no-restricted-syntax
  const sessionId = request.query.sessionId as string;
  const transport = transports[sessionId];
  if (transport) {
    await transport.handlePostMessage(request, response);
  } else {
    response.status(400).send('No transport found for sessionId');
  }
});

try {
  app.listen(PORT, () => {
    console.log(`MCP Todo Server listening on port ${PORT}`);
  });
} catch (error) {
  console.error('Failed to set up the server:', error);
  // eslint-disable-next-line unicorn/no-process-exit
  process.exit(1);
}
