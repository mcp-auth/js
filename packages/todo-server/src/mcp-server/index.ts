import { type AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { MCPAuthBearerAuthError } from 'mcp-auth';
import { z } from 'zod';

import { TodoService } from '../TodoService.js';

import {
  createTodoGuard,
  type CreateTodoSchema,
  type UpdateTodoSchema,
  type DeleteTodoSchema,
  type SearchTodoSchema,
  type SearchTodoByDateSchema,
  getTodoGuard,
  type GetTodoSchema,
  updateTodoGuard,
} from './type-guards.js';

const server = new McpServer({
  name: 'Todo MCP Server',
  version: '1.0.0',
});

const todoService = new TodoService();

const validateUser = (authInfo?: AuthInfo, requiredScopes?: string[]) => {
  if (!authInfo?.subject) {
    throw new MCPAuthBearerAuthError('invalid_token');
  }

  if (requiredScopes && !authInfo.scopes.some((scope) => requiredScopes.includes(scope))) {
    throw new MCPAuthBearerAuthError('missing_required_scopes');
  }

  return authInfo.subject;
};

server.tool(
  'create-todo',
  'Create a new todo item',
  createTodoGuard,
  async ({ title, description }: CreateTodoSchema, { authInfo }) => {
    const userId = validateUser(authInfo, ['write:todo']);

    try {
      const todo = await todoService.createTodo(userId, title, description);
      return {
        content: [{ type: 'text', text: `Created todo: ${todo.title}` }],
      };
    } catch (error) {
      if (error instanceof Error) {
        return {
          content: [{ type: 'text', text: `Error: ${error.message}` }],
          isError: true,
        };
      }
      throw error;
    }
  }
);

server.tool(
  'get-todo',
  'Get a specific todo by ID',
  getTodoGuard,
  async ({ todoId }: GetTodoSchema, { authInfo }) => {
    const userId = validateUser(authInfo, ['read:todo']);

    const todo = await todoService.getTodo(userId, todoId);
    if (!todo) {
      return {
        content: [{ type: 'text', text: 'Todo not found' }],
      };
    }

    return {
      content: [
        {
          type: 'text',
          text: `Title: ${todo.title}\nDescription: ${todo.description}\nStatus: ${todo.completed ? 'completed' : 'active'}\nCreated: ${todo.createdAt.toISOString()}\nLast Updated: ${todo.updatedAt.toISOString()}`,
        },
      ],
    };
  }
);

server.tool('list-todos', 'List all todos', {}, async (_, { authInfo }) => {
  const userId = validateUser(authInfo, ['read:todo']);

  const todos = await todoService.listTodos(userId);

  return {
    content: [
      {
        type: 'text',
        text: todos
          .map((todo) => `- ${todo.title} (${todo.completed ? 'completed' : 'active'})`)
          .join('\n'),
      },
    ],
  };
});

server.tool(
  'update-todo',
  'Update a todo item',
  updateTodoGuard,
  async ({ todoId, title, description }: UpdateTodoSchema, { authInfo }) => {
    const userId = validateUser(authInfo, ['write:todo']);

    const todo = await todoService.updateTodo(userId, todoId, title, description);
    if (!todo) {
      return {
        content: [{ type: 'text', text: 'Todo not found' }],
      };
    }
    return {
      content: [{ type: 'text', text: `Updated todo: ${todo.title}` }],
    };
  }
);

server.tool(
  'complete-todo',
  'Mark a todo as completed',
  { todoId: z.string() },
  async ({ todoId }: DeleteTodoSchema, { authInfo }) => {
    const userId = validateUser(authInfo, ['write:todo']);

    const todo = await todoService.completeTodo(userId, todoId);
    if (!todo) {
      return {
        content: [{ type: 'text', text: 'Todo not found' }],
      };
    }

    return {
      content: [{ type: 'text', text: `Marked todo as completed: ${todo.title}` }],
    };
  }
);

server.tool(
  'delete-todo',
  'Delete a todo item',
  { todoId: z.string() },
  async ({ todoId }: DeleteTodoSchema, { authInfo }) => {
    const userId = validateUser(authInfo, ['manage:todo']);

    await todoService.deleteTodo(userId, todoId);
    return {
      content: [{ type: 'text', text: 'Todo deleted successfully' }],
    };
  }
);

server.tool(
  'search-todos-by-title',
  'Search todos by title',
  { searchTerm: z.string() },
  async ({ searchTerm }: SearchTodoSchema, { authInfo }) => {
    const userId = validateUser(authInfo, ['read:todo']);

    const todos = await todoService.searchTodosByTitle(userId, searchTerm);
    return {
      content: [
        {
          type: 'text',
          text: todos
            .map((todo) => `- ${todo.title} (${todo.completed ? 'completed' : 'active'})`)
            .join('\n'),
        },
      ],
    };
  }
);

server.tool(
  'search-todos-by-date',
  'Search todos by date',
  { date: z.string() },
  async ({ date }: SearchTodoByDateSchema, { authInfo }) => {
    const userId = validateUser(authInfo, ['read:todo']);

    const todos = await todoService.searchTodosByDate(userId, date);
    return {
      content: [
        {
          type: 'text',
          text: todos
            .map((todo) => `- ${todo.title} (${todo.completed ? 'completed' : 'active'})`)
            .join('\n'),
        },
      ],
    };
  }
);

server.tool(
  'list-active-todos',
  'List all active (not completed) todos',
  {},
  async (_: Record<string, never>, { authInfo }) => {
    const userId = validateUser(authInfo, ['read:todo']);

    const todos = await todoService.listActiveTodos(userId);
    return {
      content: [
        {
          type: 'text',
          text: todos.map((todo) => `- ${todo.title}`).join('\n'),
        },
      ],
    };
  }
);

server.tool(
  'summarize-active-todos',
  'Get a summary of active todos',
  {},
  async (_, { authInfo }) => {
    const userId = validateUser(authInfo, ['read:todo']);

    const summary = await todoService.summarizeActiveTodos(userId);
    return {
      content: [{ type: 'text', text: summary }],
    };
  }
);

export default server;
