# mcp-auth

> The MCP SDK asks you to bring two things: a token verifier and your auth metadata. mcp-auth gives you both, for any OAuth / OIDC provider.

[Get started](https://mcp-auth.dev/docs) · [Sample servers](https://github.com/mcp-auth/js/tree/master/packages/sample-servers) · [Provider list](https://mcp-auth.dev/provider-list)

The MCP TypeScript SDK v2 (`@modelcontextprotocol/server`) ships the entire HTTP layer of MCP authorization itself: `requireBearerAuth`, `verifyBearerToken`, `oauthMetadataResponse`, and official framework adapters like `@modelcontextprotocol/express`. What it leaves to you is provider integration — verifying the access tokens your OAuth 2.0 / OpenID Connect provider issues, and describing that provider in your server's metadata.

That is exactly what mcp-auth does:

1. **A token verifier** — `MCPAuth` implements the SDK's `OAuthTokenVerifier` interface. It discovers your provider's metadata, fetches its JWKS, and verifies JWT access tokens (signature, issuer, audience, expiration, and the claims MCP servers need), with sensible caching throughout. `mcpAuth.getBearerAuthOptions()` bundles the verifier with the RFC 9728 metadata URL into the SDK's `BearerAuthOptions`, ready for `requireBearerAuth`.
2. **Your auth metadata** — `mcpAuth.getAuthMetadataOptions()` returns the SDK's `AuthMetadataOptions`, ready to serve the OAuth discovery documents.

It implements the authorization requirements of the [latest MCP specification](https://modelcontextprotocol.io/specification/latest/basic/authorization) and works with any OAuth 2.0 / OpenID Connect provider that meets them. Check out the [MCP-compatible providers](https://mcp-auth.dev/docs/provider-list) list for real-time compatibility checks.

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

The fastest way to get started is the [step-by-step guide](https://mcp-auth.dev/docs). For complete runnable examples — `whoami` and `todo-manager` as Cloudflare Workers, plus an Express variant — see the [sample servers](https://github.com/mcp-auth/js/tree/master/packages/sample-servers) in this repository.

## Configuration highlights

- `protectedResourceMetadata` is your RFC 9728 Protected Resource Metadata declaration: everything in it is published through the SDK's metadata helpers, and the token verifier enforces what it declares — the `aud` claim must match `resource`, the `iss` claim must match the configured authorization server.
- `authorizationServer` accepts a discovery config (`{ issuer, type }`, metadata fetched lazily and cached — safe for edge runtimes where module-init network calls are not allowed) or a resolved config with metadata (hardcoded or pre-fetched via `fetchServerConfig()`).
- Audience (`aud`) validation always expects your `resource` identifier and cannot be redirected or disabled: the MCP authorization specification requires access tokens to be bound to the resource they are issued for (RFC 8707), so tokens without a matching `aud` claim are rejected.
- `jwtVerifyOptions` passes options through to [jose](https://github.com/panva/jose)'s `jwtVerify` for advanced tuning (clock tolerance, required claims, etc.); `issuer` and `audience` are excluded — they always come from the metadata declaration.
- Verified tokens are surfaced as `McpAuthInfo` — the SDK's `AuthInfo` plus guaranteed `issuer`, `subject`, and the full `claims` payload.

## Opaque access tokens

`MCPAuth` verifies JWT access tokens against your provider's JWKS. Some authorization servers issue opaque access tokens instead — random strings with nothing to verify locally. The two halves of mcp-auth are decoupled, so this case is covered by bringing your own verifier: implement the SDK's `OAuthTokenVerifier` against your server's token introspection endpoint ([RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662)), and keep using the metadata half — the discovery documents, the challenge URL, and `getAuthInfo()` all work unchanged.

```ts
import {
  OAuthError,
  OAuthErrorCode,
  requireBearerAuth,
  type OAuthTokenVerifier,
} from '@modelcontextprotocol/server';
import { MCPAuth, type McpAuthInfo } from 'mcp-auth';

const issuer = 'https://auth.example.com/oidc';
const resource = 'https://api.example.com/mcp';

// The metadata half works exactly as in the examples above
const mcpAuth = new MCPAuth({
  protectedResourceMetadata: {
    resource,
    authorizationServer: { issuer, type: 'oidc' },
    scopesSupported: ['read:notes'],
  },
});

const introspectionEndpoint = 'https://auth.example.com/oidc/token/introspection';
// A confidential client registered with the authorization server (e.g. a machine-to-machine
// app) — most servers require one to introspect tokens issued to other clients
const clientId = 'your-m2m-client-id';
const clientSecret = 'your-m2m-client-secret';

const introspectionVerifier: OAuthTokenVerifier = {
  async verifyAccessToken(token): Promise<McpAuthInfo> {
    let response: Response;

    try {
      response = await fetch(introspectionEndpoint, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          authorization: `Basic ${btoa(`${clientId}:${clientSecret}`)}`,
        },
        body: new URLSearchParams({ token, token_type_hint: 'access_token' }),
        signal: AbortSignal.timeout(5000),
      });
    } catch (error) {
      /*
       * A plain `Error`, not an `OAuthError`: the SDK answers 500. The token could not be
       * verified, which is different from being invalid — a 401 would send a client with a
       * perfectly fine token into a pointless re-authorization.
       */
      throw new Error('Failed to reach the token introspection endpoint.', { cause: error });
    }

    if (!response.ok) {
      throw new Error(`Introspection request failed with status ${response.status}.`);
    }

    const data = (await response.json()) as McpAuthInfo['claims'];

    // The MCP spec still requires these checks — introspection does not exempt them
    if (data.active !== true) {
      throw new OAuthError(OAuthErrorCode.InvalidToken, 'The token is not active.');
    }

    if (!(Array.isArray(data.aud) ? data.aud : [data.aud]).includes(resource)) {
      throw new OAuthError(OAuthErrorCode.InvalidToken, 'The token audience does not match.');
    }

    if (typeof data.iss === 'string' && data.iss !== issuer) {
      throw new OAuthError(OAuthErrorCode.InvalidToken, 'The token issuer is not trusted.');
    }

    if (typeof data.sub !== 'string' || typeof data.exp !== 'number') {
      throw new OAuthError(OAuthErrorCode.InvalidToken, 'The token has no `sub` or `exp`.');
    }

    // The `McpAuthInfo` shape, so `getAuthInfo()` in tool callbacks works unchanged
    return {
      token,
      issuer,
      subject: data.sub,
      clientId: typeof data.client_id === 'string' ? data.client_id : '',
      scopes: typeof data.scope === 'string' ? data.scope.split(' ').filter(Boolean) : [],
      expiresAt: data.exp,
      claims: data,
    };
  },
};

// Only the gate changes; the discovery documents still come from `mcpAuth` as shown above
const gate = requireBearerAuth({
  verifier: introspectionVerifier,
  resourceMetadataUrl: mcpAuth.resourceMetadataUrl,
  requiredScopes: ['read:notes'],
});
```

A few things to know:

- **The endpoint**: some servers advertise it as `introspection_endpoint` in their metadata, others keep it off the public discovery document entirely (e.g. an internal admin API). Configure whatever yours is.
- **The credentials**: most servers only let authenticated confidential clients introspect tokens issued to other clients; some deployments protect the endpoint at the network level instead. Check your server's policy.
- **The cost**: every request is an introspection round-trip. That is also the point — revoked tokens are rejected immediately. Add caching only if you accept the revocation delay.

## Join the discussion

Join the [MCP Auth org discussion](https://github.com/orgs/mcp-auth/discussions) to ask questions or share your feedback.
