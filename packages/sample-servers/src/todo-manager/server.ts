import { McpServer, type CallToolResult } from '@modelcontextprotocol/server';
import { getAuthInfo } from 'mcp-auth';
import { z } from 'zod';

import { TodoService } from './todo-service.js';

/**
 * TodoService is shared across requests within a Worker isolate so the sample can demonstrate
 * state. Use a real store (KV, D1, Durable Objects) in production.
 */
const todoService = new TodoService();

const errorResult = (message: string): CallToolResult => ({
  content: [{ type: 'text', text: JSON.stringify({ error: message }) }],
  isError: true,
});

/**
 * The factory creates a fresh MCP server instance per request, keeping requests isolated.
 */
export const createMcpServer = () => {
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
       * Users can delete their own todos; the 'delete:todos' scope allows deleting any todo
       */
      const canDelete = todo.ownerId === userId || scopes.includes('delete:todos');

      if (!canDelete) {
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
