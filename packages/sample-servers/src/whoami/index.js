/**
 * This is the JavaScript version of the WhoAmI server.
 *
 * @see {@link https://mcp-auth.dev/docs/tutorials/whoami Tutorial} for the full tutorial.
 * @see {@link file://./index.ts} for the TypeScript version.
 */
import {
  createMcpExpressApp,
  mcpAuthMetadataRouter,
  requireBearerAuth,
} from '@modelcontextprotocol/express';
import { NodeStreamableHTTPServerTransport } from '@modelcontextprotocol/node';
import { McpServer } from '@modelcontextprotocol/server';
import { configDotenv } from 'dotenv';
import { getAuthInfo, MCPAuth } from 'mcp-auth';

configDotenv();

// Factory function to create an MCP server instance
// In stateless mode, each request needs its own server instance
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

const { MCP_AUTH_ISSUER, MCP_RESOURCE_IDENTIFIER } = process.env;

if (!MCP_AUTH_ISSUER) {
  throw new Error('MCP_AUTH_ISSUER environment variable is required');
}

if (!MCP_RESOURCE_IDENTIFIER) {
  throw new Error('MCP_RESOURCE_IDENTIFIER environment variable is required');
}

const mcpAuth = new MCPAuth({
  resource: MCP_RESOURCE_IDENTIFIER,
  authorizationServer: { issuer: MCP_AUTH_ISSUER, type: 'oidc' },
});

const PORT = 3001;
const app = createMcpExpressApp();

// Serve the OAuth discovery documents (`/.well-known/...`)
app.use(mcpAuthMetadataRouter(await mcpAuth.getAuthMetadataOptions()));

app.post(
  '/',
  // Require a valid Bearer token, verified by the `MCPAuth` instance
  requireBearerAuth(mcpAuth.getBearerAuthOptions()),
  async (request, response) => {
    // In stateless mode, create a new instance of transport and server for each request
    // to ensure complete isolation. A single instance would cause request ID collisions
    // when multiple clients connect concurrently.
    const mcpServer = createMcpServer();
    const transport = new NodeStreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    await mcpServer.connect(transport);
    await transport.handleRequest(request, response, request.body);
    response.on('close', () => {
      transport.close();
      mcpServer.close();
    });
  }
);

app.listen(PORT);
