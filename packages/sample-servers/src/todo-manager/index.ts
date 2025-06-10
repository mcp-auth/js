import assert from 'node:assert';

import { type AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { configDotenv } from 'dotenv';
import express from 'express';
import { fetchServerConfig, MCPAuth, MCPAuthBearerAuthError } from 'mcp-auth';
import { z } from 'zod';

import { TodoService } from './todo-service.js';

configDotenv();

const todoService = new TodoService();

const assertUserId = (authInfo?: AuthInfo) => {
  const { subject } = authInfo ?? {};
  assert(subject, 'Invalid auth info');
  return subject;
};

const hasRequiredScopes = (userScopes: string[], requiredScopes: string[]): boolean => {
  return requiredScopes.every((scope) => userScopes.includes(scope));
};

// Create an MCP server
const server = new McpServer({
  name: 'Todo Manager',
  version: '0.0.0',
});

server.tool(
  'create-todo',
  'Create a new todo',
  { content: z.string() },
  ({ content }: { content: string }, { authInfo }) => {
    const userId = assertUserId(authInfo);

    /**
     * Only users with 'create:todos' scope can create todos
     */
    if (!hasRequiredScopes(authInfo?.scopes ?? [], ['create:todos'])) {
      throw new MCPAuthBearerAuthError('missing_required_scopes');
    }

    const createdTodo = todoService.createTodo({ content, ownerId: userId });

    return {
      content: [{ type: 'text', text: JSON.stringify(createdTodo) }],
    };
  }
);

server.tool('get-todos', 'List all todos', ({ authInfo }) => {
  const userId = assertUserId(authInfo);

  /**
   * If user has 'read:todos' scope, they can access all todos (todoOwnerId = undefined)
   * If user doesn't have 'read:todos' scope, they can only access their own todos (todoOwnerId = userId)
   */
  const todoOwnerId = hasRequiredScopes(authInfo?.scopes ?? [], ['read:todos'])
    ? undefined
    : userId;

  const todos = todoService.getAllTodos(todoOwnerId);

  return {
    content: [{ type: 'text', text: JSON.stringify(todos) }],
  };
});

server.tool(
  'delete-todo',
  'Delete a todo by id',
  { id: z.string() },
  ({ id }: { id: string }, { authInfo }) => {
    const userId = assertUserId(authInfo);

    const todo = todoService.getTodoById(id);

    if (!todo) {
      return {
        content: [{ type: 'text', text: JSON.stringify({ error: 'Failed to delete todo' }) }],
      };
    }

    /**
     * Users can only delete their own todos
     * Users with 'delete:todos' scope can delete any todo
     */
    if (todo.ownerId !== userId && !hasRequiredScopes(authInfo?.scopes ?? [], ['delete:todos'])) {
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({ error: 'Failed to delete todo' }),
          },
        ],
      };
    }

    const deletedTodo = todoService.deleteTodo(id);

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            message: `Todo ${id} deleted`,
            details: deletedTodo,
          }),
        },
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
  /**
   * Todo @xiaoyijun remove this once the protected resource metadata is supported, this is only for demonstration purpose in pull request.
   */
  protectedResource: {
    metadata: {
      resource: 'http://localhost:3001',
      authorizationServers: [authServerConfig],
      scopesSupported: ['read:todos', 'create:todos', 'delete:todos'],
    },
  },
});

const PORT = 3001;
const app = express();

app.use(mcpAuth.protectedResourceMetadataRouter());
app.use(mcpAuth.bearerAuth('jwt'));

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
