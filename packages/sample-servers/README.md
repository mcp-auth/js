# MCP Auth sample servers

This package contains sample servers that demonstrate how to use the MCP Auth Node.js SDK in various scenarios.

See [the documentation](https://mcp-auth.dev/docs) for the full guide.

## Get started

### WhoAmI MCP server

A simple server that demonstrates basic authentication. It provides a single tool:

- `whoami`: Returns the authenticated user's information

To run the WhoAmI server:
```bash
# TypeScript version (with watch mode)
pnpm dev:whoami

# Start the built version
pnpm start:whoami

# JavaScript version
pnpm start:whoami:js
```

### Todo manager MCP server

A more complex example demonstrating authentication and authorization with different permission scopes. It provides the following tools:

- `create-todo`: Create a new todo (requires `create:todos` scope)
- `get-todos`: List todos (requires `read:todos` scope for all todos)
- `delete-todo`: Delete a todo (requires `delete:todos` scope for others' todos)

To run the Todo Manager server:
```bash
# TypeScript version (with watch mode)
pnpm dev:todo-manager

# Start the built version
pnpm start:todo-manager
```

## Environment variables

### WhoAmI server

- `MCP_AUTH_ISSUER`: The issuer URL of your authorization server (e.g., `https://your-tenant.logto.app/oidc`)

### Todo manager server

- `MCP_AUTH_ISSUER`: The issuer URL of your authorization server (e.g., `https://your-tenant.logto.app/oidc`)
- `MCP_RESOURCE_IDENTIFIER`: The resource identifier for the protected resource (e.g., `https://todo.example.com/api/`). Note: The trailing slash is recommended due to an MCP SDK behavior that appends `/` when constructing resource indicators.
