import { McpServer } from '@modelcontextprotocol/server';
import { getAuthInfo } from 'mcp-auth';

/**
 * The factory creates a fresh MCP server instance per request, keeping requests isolated.
 */
export const createMcpServer = () => {
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
