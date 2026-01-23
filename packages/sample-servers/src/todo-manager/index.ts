import assert from 'node:assert';

import { type AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { configDotenv } from 'dotenv';
import express from 'express';
import { MCPAuth, MCPAuthBearerAuthError } from 'mcp-auth';
import { z } from 'zod';

import { TodoService } from './todo-service.js';

configDotenv();

const { MCP_AUTH_ISSUER, MCP_RESOURCE_IDENTIFIER } = process.env;

if (!MCP_AUTH_ISSUER) {
  throw new Error('MCP_AUTH_ISSUER environment variable is required');
}

if (!MCP_RESOURCE_IDENTIFIER) {
  throw new Error('MCP_RESOURCE_IDENTIFIER environment variable is required');
}

const todoService = new TodoService();

const assertUserId = (authInfo?: AuthInfo) => {
  assert(authInfo?.subject, 'Invalid auth info');
  return authInfo.subject;
};

const hasRequiredScopes = (userScopes: string[], requiredScopes: string[]): boolean => {
  return requiredScopes.every((scope) => userScopes.includes(scope));
};

// Create an MCP server
const server = new McpServer({
  name: 'Todo Manager',
  version: '0.0.0',
});

server.registerTool(
  'create-todo',
  {
    description: 'Create a new todo',
    inputSchema: { content: z.string() },
  },
  ({ content }, { authInfo }) => {
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

server.registerTool(
  'get-todos',
  {
    description: 'List all todos',
    inputSchema: {},
  },
  (_params, { authInfo }) => {
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
  }
);

server.registerTool(
  'delete-todo',
  {
    description: 'Delete a todo by id',
    inputSchema: { id: z.string() },
  },
  ({ id }, { authInfo }) => {
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

const mcpAuth = new MCPAuth({
  protectedResources: {
    metadata: {
      resource: MCP_RESOURCE_IDENTIFIER,
      authorizationServers: [{ issuer: MCP_AUTH_ISSUER, type: 'oidc' }],
      scopesSupported: ['create:todos', 'read:todos', 'delete:todos'],
    },
  },
});

const PORT = 3001;
const app = express();

app.use(mcpAuth.protectedResourceMetadataRouter());
app.use(
  mcpAuth.bearerAuth('jwt', {
    resource: MCP_RESOURCE_IDENTIFIER,
    audience: MCP_RESOURCE_IDENTIFIER,
  })
);

app.post('/', async (request, response) => {
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  await server.connect(transport);
  await transport.handleRequest(request, response, request.body);
  response.on('close', () => {
    void transport.close();
  });
});

app.listen(PORT);
