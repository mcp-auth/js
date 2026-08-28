# MCP Auth sample servers

Sample MCP servers demonstrating [mcp-auth](https://github.com/mcp-auth/js/tree/master/packages/mcp-auth) with the fetch-native MCP TypeScript SDK v2, built as Cloudflare Workers with [Hono](https://hono.dev) and runnable locally with `wrangler dev` — no Cloudflare account needed for local development.

Each sample separates the MCP server from the auth wiring, so the two concerns can be read (and taught) independently:

```
src/<sample>/
  server.ts   The MCP server definition: tools reading the verified identity via `getAuthInfo`
  auth.ts     The mcp-auth wiring: the `MCPAuth` instance and two Hono middlewares
              (`oauthDiscovery` for the well-known documents, `bearerAuth` for token verification)
  index.ts    The Hono app composing them
```

See [the documentation](https://mcp-auth.dev/docs) for the full guide.

## Samples

### WhoAmI

The minimal wiring: verify JWT access tokens with `MCPAuth`, serve the OAuth discovery documents, and read the verified identity in a tool with `getAuthInfo`. It provides a single tool:

- `whoami`: Returns the authenticated user's token claims

### Todo manager

Authorization with different permission scopes on top of the same wiring:

- `create-todo`: Create a todo (requires the `create:todos` scope, enforced via `getAuthInfo`)
- `get-todos`: List todos (the `read:todos` scope widens the listing from own todos to all todos)
- `delete-todo`: Delete a todo (own todos, or any todo with the `delete:todos` scope)

## Get started

1. Configure the environment for local development:

   ```bash
   cp .dev.vars.example .dev.vars
   ```

   - `MCP_AUTH_ISSUER`: The issuer URL of your authorization server (e.g., `https://your-tenant.logto.app/oidc`)
   - `MCP_RESOURCE_IDENTIFIER`: The resource identifier of the MCP server (`http://localhost:8787` for local development). Register it at your provider and request tokens for it — access tokens must carry it as their `aud` (audience) claim.

2. Run a sample:

   ```bash
   pnpm dev:whoami
   # or
   pnpm dev:todo-manager
   ```

   The server listens on `http://localhost:8787`. Connect to it with an MCP client (e.g. the [MCP Inspector](https://github.com/modelcontextprotocol/inspector)) and complete the OAuth flow.

To deploy to Cloudflare, set the two variables for the Worker and run `pnpm deploy:whoami` / `pnpm deploy:todo-manager`.
