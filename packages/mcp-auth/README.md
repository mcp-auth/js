# mcp-auth

> The MCP SDK asks you to bring two things: a token verifier and your auth metadata. mcp-auth gives you both, for any OAuth / OIDC provider.

The MCP TypeScript SDK v2 (`@modelcontextprotocol/server`) ships the entire HTTP layer of MCP authorization itself: `requireBearerAuth`, `verifyBearerToken`, `oauthMetadataResponse`, and official framework adapters like `@modelcontextprotocol/express`. What it leaves to you is provider integration — verifying the access tokens your OAuth 2.0 / OpenID Connect provider issues, and describing that provider in your server's metadata.

That is exactly what mcp-auth does:

1. **A token verifier** — `MCPAuth` implements the SDK's `OAuthTokenVerifier` interface. It discovers your provider's metadata, fetches its JWKS, and verifies JWT access tokens (signature, issuer, audience, expiration, and the claims MCP servers need), with sensible caching throughout. `mcpAuth.getBearerAuthOptions()` bundles the verifier with the RFC 9728 metadata URL into the SDK's `BearerAuthOptions`, ready for `requireBearerAuth`.
2. **Your auth metadata** — `mcpAuth.getAuthMetadataOptions()` returns the SDK's `AuthMetadataOptions`, ready to serve the OAuth discovery documents.

It works with any provider that meets the MCP authorization requirements. Check out the [MCP-compatible providers](https://mcp-auth.dev/docs/provider-list) list for real-time compatibility checks.

## Installation

```bash
npm install mcp-auth @modelcontextprotocol/server
```

`@modelcontextprotocol/server` v2 is a peer dependency. Node.js >= 20; ESM only.

Still on MCP SDK v1 (`@modelcontextprotocol/sdk`)? Stay on the 0.2 line — `npm install mcp-auth@0.2` — and see the [v0.2.0 code and samples](https://github.com/mcp-auth/js/tree/v0.2.0).

## Usage

### Fetch-native runtimes (Cloudflare Workers, Deno, Bun, Node.js)

```ts
import {
  createMcpHandler,
  McpServer,
  oauthMetadataResponse,
  requireBearerAuth,
} from '@modelcontextprotocol/server';
import { getAuthInfo, MCPAuth } from 'mcp-auth';

const mcpAuth = new MCPAuth({
  protectedResourceMetadata: {
    resource: 'https://api.example.com/mcp',
    authorizationServer: { issuer: 'https://auth.example.com/oidc', type: 'oidc' },
    scopesSupported: ['read:notes'],
  },
});

const createServer = () => {
  const server = new McpServer({ name: 'Notes', version: '1.0.0' });
  server.registerTool('whoami', { description: 'Get the current user' }, (ctx) => {
    const { subject, claims } = getAuthInfo(ctx);
    return { content: [{ type: 'text', text: JSON.stringify({ subject, claims }) }] };
  });
  return server;
};

const handler = createMcpHandler(createServer);
const gate = requireBearerAuth(mcpAuth.getBearerAuthOptions({ requiredScopes: ['read:notes'] }));

export default {
  async fetch(request: Request): Promise<Response> {
    // Serve the OAuth discovery documents; the path guard keeps the (lazily fetched)
    // metadata resolution off the request path of regular MCP traffic
    if (new URL(request.url).pathname.startsWith('/.well-known/')) {
      const metadataResponse = oauthMetadataResponse(request, await mcpAuth.getAuthMetadataOptions());
      if (metadataResponse) {
        return metadataResponse;
      }
    }

    // Require a valid Bearer token for everything else
    const auth = await gate(request);
    if (auth instanceof Response) {
      return auth;
    }

    return handler.fetch(request, { authInfo: auth });
  },
};
```

### Express (via `@modelcontextprotocol/express`)

```ts
import {
  createMcpExpressApp,
  mcpAuthMetadataRouter,
  requireBearerAuth,
} from '@modelcontextprotocol/express';
import { toNodeHandler } from '@modelcontextprotocol/node';
import { createMcpHandler } from '@modelcontextprotocol/server';
import { MCPAuth } from 'mcp-auth';

const mcpAuth = new MCPAuth({
  protectedResourceMetadata: {
    resource: 'https://api.example.com/mcp',
    authorizationServer: { issuer: 'https://auth.example.com/oidc', type: 'oidc' },
    scopesSupported: ['read:notes'],
  },
});

// Reuses `createServer` from the fetch-native example above
const mcpNodeHandler = toNodeHandler(createMcpHandler(createServer));

const app = createMcpExpressApp();
app.use(mcpAuthMetadataRouter(await mcpAuth.getAuthMetadataOptions()));
app.all(
  '/mcp',
  requireBearerAuth(mcpAuth.getBearerAuthOptions({ requiredScopes: ['read:notes'] })),
  /*
   * `createMcpExpressApp` applies `express.json()`, which drains the request stream, so the
   * parsed body is passed along explicitly.
   */
  async (request, response) => mcpNodeHandler(request, response, request.body)
);
app.listen(3000);
```

See [the documentation](https://mcp-auth.dev) for the full guide, and the [sample servers](https://github.com/mcp-auth/js/tree/master/packages/sample-servers) in this repository for complete runnable examples.

## Configuration highlights

- `protectedResourceMetadata` is your RFC 9728 Protected Resource Metadata declaration: everything in it is published through the SDK's metadata helpers, and the token verifier enforces what it declares — the `aud` claim must match `resource`, the `iss` claim must match the configured authorization server.
- `authorizationServer` accepts a discovery config (`{ issuer, type }`, metadata fetched lazily and cached — safe for edge runtimes where module-init network calls are not allowed) or a resolved config with metadata (hardcoded or pre-fetched via `fetchServerConfig()`).
- Audience (`aud`) validation always expects your `resource` identifier and cannot be redirected or disabled: the MCP authorization specification requires access tokens to be bound to the resource they are issued for (RFC 8707), so tokens without a matching `aud` claim are rejected.
- `jwtVerifyOptions` passes options through to [jose](https://github.com/panva/jose)'s `jwtVerify` for advanced tuning (clock tolerance, required claims, etc.); `issuer` and `audience` are excluded — they always come from the metadata declaration.
- Verified tokens are surfaced as `McpAuthInfo` — the SDK's `AuthInfo` plus guaranteed `issuer`, `subject`, and the full `claims` payload.

## Join the discussion

Join the [MCP Auth org discussion](https://github.com/orgs/mcp-auth/discussions) to ask questions or share your feedback.
