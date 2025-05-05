# MCP Auth Node.js SDK

The MCP specification [requires OAuth 2.1 and other RFCs](https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization) for authorization. Instead of implementing all the OAuth 2.1 and OpenID Connect standards yourself, a **production-ready provider** and a set of **libraries and tutorials** can save you a lot of time and effort.

That's where MCP Auth comes in. It includes:

1. An updated OAuth 2.1 and OpenID Connect provider list that meets the MCP requirements.
2. A set of provider-agnostic libraries and tools to help you integrate your MCP server with any compliant provider.
3. Practical tutorials and examples to get you started quickly.

And yes, it can be as simple as a few lines of code:

```ts
const server = new McpServer(/* ... */);
const mcpAuth = new MCPAuth({
  server: await fetchServerConfig('<auth-server-url>', { type: 'oidc' }),
});
const app = express();

app.use(mcpAuth.bearerAuth('jwt', { requiredScopes: ['read', 'write'] }));
server.tool('whoami', ({ authInfo }) => {
  // Use `authInfo` to access the auth information carried from `req.auth`
});
```

See [the documentation](https://mcp-auth.dev) for the full guide.
