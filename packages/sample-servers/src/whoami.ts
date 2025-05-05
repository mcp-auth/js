import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { configDotenv } from 'dotenv';
import express from 'express';
import {
  fetchServerConfig,
  MCPAuth,
  MCPAuthTokenVerificationError,
  type VerifyAccessTokenFunction,
} from 'mcp-auth';

configDotenv();

// Create an MCP server
const server = new McpServer({
  name: 'WhoAmI',
  version: '0.0.0',
});

// Add a tool to the server that returns the current user's information
server.tool('whoami', ({ authInfo }) => {
  return {
    content: [
      { type: 'text', text: JSON.stringify(authInfo?.claims ?? { error: 'Not authenticated' }) },
    ],
  };
});

const { MCP_AUTH_ISSUER } = process.env;

if (!MCP_AUTH_ISSUER) {
  throw new Error('MCP_AUTH_ISSUER environment variable is required');
}

const mcpAuth = new MCPAuth({
  server: await fetchServerConfig(MCP_AUTH_ISSUER, { type: 'oidc' }),
});

/**
 * Verifies the provided Bearer token by fetching user information from the authorization server.
 * If the token is valid, it returns an `AuthInfo` object containing the user's information.
 */
const verifyToken: VerifyAccessTokenFunction = async (token) => {
  const { userinfoEndpoint } = mcpAuth.config.server.metadata;

  if (!userinfoEndpoint) {
    throw new Error('Userinfo endpoint is not configured in the server metadata');
  }

  const response = await fetch(userinfoEndpoint, {
    headers: { Authorization: `Bearer ${token}` },
  });

  if (!response.ok) {
    throw new MCPAuthTokenVerificationError('token_verification_failed', response);
  }

  const userInfo: unknown = await response.json();

  if (typeof userInfo !== 'object' || userInfo === null || !('sub' in userInfo)) {
    throw new MCPAuthTokenVerificationError('invalid_token', response);
  }

  return {
    token,
    issuer: MCP_AUTH_ISSUER,
    subject: String(userInfo.sub), // 'sub' is a standard claim for the subject (user's ID)
    clientId: '', // Client ID is not used in this example, but can be set if needed
    scopes: [],
    claims: userInfo,
  };
};

const PORT = 3001;
const app = express();

app.use(mcpAuth.delegatedRouter());
app.use(mcpAuth.bearerAuth(verifyToken));

// Below is the boilerplate code from MCP SDK documentation
const transports: Record<string, SSEServerTransport> = {};

// eslint-disable-next-line unicorn/prevent-abbreviations
app.get('/sse', async (_req, res) => {
  // Create SSE transport for legacy clients
  const transport = new SSEServerTransport('/messages', res);
  // eslint-disable-next-line @silverhand/fp/no-mutation
  transports[transport.sessionId] = transport;

  res.on('close', () => {
    // eslint-disable-next-line @silverhand/fp/no-delete, @typescript-eslint/no-dynamic-delete
    delete transports[transport.sessionId];
  });

  await server.connect(transport);
});

// eslint-disable-next-line unicorn/prevent-abbreviations
app.post('/messages', async (req, res) => {
  const sessionId = String(req.query.sessionId);
  const transport = transports[sessionId];
  if (transport) {
    await transport.handlePostMessage(req, res, req.body);
  } else {
    res.status(400).send('No transport found for sessionId');
  }
});

app.listen(PORT);
