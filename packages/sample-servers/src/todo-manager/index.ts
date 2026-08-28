import {
  createMcpExpressApp,
  mcpAuthMetadataRouter,
  requireBearerAuth,
} from '@modelcontextprotocol/express';
import { NodeStreamableHTTPServerTransport } from '@modelcontextprotocol/node';
import { McpServer, type CallToolResult } from '@modelcontextprotocol/server';
import { configDotenv } from 'dotenv';
import { getAuthInfo, MCPAuth } from 'mcp-auth';
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

// TodoService is a singleton since we need to share state across requests
const todoService = new TodoService();

const errorResult = (message: string): CallToolResult => ({
  content: [{ type: 'text', text: JSON.stringify({ error: message }) }],
  isError: true,
});

// Factory function to create an MCP server instance
// In stateless mode, each request needs its own server instance
const createMcpServer = () => {
  const mcpServer = new McpServer({
    name: 'Todo Manager',
    version: '0.0.0',
  });

  mcpServer.registerTool(
    'create-todo',
    {
      description: 'Create a new todo',
      inputSchema: z.object({ content: z.string() }),
    },
    ({ content }, context) => {
      /**
       * Only users with 'create:todos' scope can create todos; `getAuthInfo` throws otherwise
       * and the SDK surfaces the error to the model as a tool error result.
       */
      const { subject: userId } = getAuthInfo(context, { requiredScopes: ['create:todos'] });

      const createdTodo = todoService.createTodo({ content, ownerId: userId });

      return {
        content: [{ type: 'text', text: JSON.stringify(createdTodo) }],
      };
    }
  );

  mcpServer.registerTool(
    'get-todos',
    {
      description: 'List all todos',
    },
    (context) => {
      const { subject: userId, scopes } = getAuthInfo(context);

      /**
       * If user has 'read:todos' scope, they can access all todos (todoOwnerId = undefined)
       * If user doesn't have 'read:todos' scope, they can only access their own todos (todoOwnerId = userId)
       */
      const todoOwnerId = scopes.includes('read:todos') ? undefined : userId;

      const todos = todoService.getAllTodos(todoOwnerId);

      return {
        content: [{ type: 'text', text: JSON.stringify(todos) }],
      };
    }
  );

  mcpServer.registerTool(
    'delete-todo',
    {
      description: 'Delete a todo by id',
      inputSchema: z.object({ id: z.string() }),
    },
    ({ id }, context) => {
      const { subject: userId, scopes } = getAuthInfo(context);

      const todo = todoService.getTodoById(id);

      if (!todo) {
        return errorResult('Failed to delete todo');
      }

      /**
       * Users can only delete their own todos
       * Users with 'delete:todos' scope can delete any todo
       */
      if (todo.ownerId !== userId && !scopes.includes('delete:todos')) {
        return errorResult('Failed to delete todo');
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

  return mcpServer;
};

const mcpAuth = new MCPAuth({
  resource: MCP_RESOURCE_IDENTIFIER,
  authorizationServer: { issuer: MCP_AUTH_ISSUER, type: 'oidc' },
  scopesSupported: ['create:todos', 'read:todos', 'delete:todos'],
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
      void transport.close();
      void mcpServer.close();
    });
  }
);

app.listen(PORT);
