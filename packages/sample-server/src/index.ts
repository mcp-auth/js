import { McpServer, ResourceTemplate } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { configDotenv } from 'dotenv';
import express from 'express';
import { fetchServerConfig, MCPAuth } from 'mcp-auth';
import { z } from 'zod';

configDotenv();

// Create an MCP server
const server = new McpServer({
  name: 'Demo',
  version: '1.0.0',
});

// Add an addition tool
server.tool('add', { a: z.number(), b: z.number() }, async ({ a, b }, { authInfo }) => {
  console.log('Auth Info:', authInfo);
  return {
    content: [{ type: 'text', text: String(a + b) }],
  };
});

// Add a dynamic greeting resource
server.resource(
  'greeting',
  new ResourceTemplate('greeting://{name}', { list: undefined }),
  async (uri, { name }) => ({
    contents: [
      {
        uri: uri.href,
        text: `Hello, ${typeof name === 'string' ? name : 'world'}!`,
      },
    ],
  })
);

const transport: StreamableHTTPServerTransport = new StreamableHTTPServerTransport({
  sessionIdGenerator: undefined, // Set to undefined for stateless servers
});

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

const PORT = 3234;
const app = express();

app.use(
  mcpAuth.proxyRouter(`http://localhost:${PORT}`, {
    proxyOptions: {
      on: {
        error: (error) => {
          console.error('Proxy error:', error);
        },
      },
    },
  })
);

app.post('/mcp', mcpAuth.bearerAuth('jwt'), async (request, response) => {
  console.log('Received MCP request:', request.body);
  try {
    await transport.handleRequest(request, response, request.body);
  } catch (error) {
    console.error('Error handling MCP request:', error);
    if (!response.headersSent) {
      response.status(500).json({
        jsonrpc: '2.0',
        error: {
          code: -32_603,
          message: 'Internal server error',
        },
        id: null,
      });
    }
  }
});

try {
  await server.connect(transport);
  app.listen(PORT, () => {
    console.log(`MCP Streamable HTTP Server listening on port ${PORT}`);
  });
} catch (error) {
  console.error('Failed to set up the server:', error);
  // eslint-disable-next-line unicorn/no-process-exit
  process.exit(1);
}
