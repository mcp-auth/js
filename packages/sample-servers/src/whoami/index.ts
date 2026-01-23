/**
 * This is the TypeScript version of the WhoAmI server.
 *
 * @see {@link https://mcp-auth.dev/docs/tutorials/whoami Tutorial} for the full tutorial.
 * @see {@link file://./whoami.js} for the JavaScript version.
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
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
server.registerTool(
  'whoami',
  {
    description: 'Get the current user information',
    inputSchema: {},
  },
  (_params, { authInfo }) => {
    return {
      content: [
        { type: 'text', text: JSON.stringify(authInfo?.claims ?? { error: 'Not authenticated' }) },
      ],
    };
  }
);

const { MCP_AUTH_ISSUER } = process.env;

if (!MCP_AUTH_ISSUER) {
  throw new Error('MCP_AUTH_ISSUER environment variable is required');
}

const authServerConfig = await fetchServerConfig(MCP_AUTH_ISSUER, { type: 'oidc' });

const mcpAuth = new MCPAuth({
  server: authServerConfig,
});

/**
 * Verifies the provided Bearer token by fetching user information from the authorization server.
 * If the token is valid, it returns an `AuthInfo` object containing the user's information.
 */
const verifyToken: VerifyAccessTokenFunction = async (token) => {
  const { issuer, userinfoEndpoint } = authServerConfig.metadata;

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
    issuer,
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

app.post('/', async (request, response) => {
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  await server.connect(transport);
  await transport.handleRequest(request, response, request.body);
  response.on('close', () => {
    void transport.close();
  });
});

app.listen(PORT);
