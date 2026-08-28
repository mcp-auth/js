---
'mcp-auth': major
---

Ground-up, fetch-native rewrite targeting MCP TypeScript SDK v2 (`@modelcontextprotocol/server`).

MCP SDK v2 now ships the entire HTTP consumption layer itself (`requireBearerAuth`, `verifyBearerToken`, `oauthMetadataResponse`, and official framework adapters), so mcp-auth no longer wraps any of it. Its job is now to supply the two inputs the SDK asks you to bring: a token verifier and your auth metadata.

- `MCPAuth` implements the SDK's `OAuthTokenVerifier` interface — pass the instance directly as the `verifier` to `requireBearerAuth`. One instance represents one protected resource (`resource`) trusting one authorization server (`authorizationServer`).
- `mcpAuth.getAuthMetadataOptions()` returns the SDK's `AuthMetadataOptions` for `oauthMetadataResponse` / `mcpAuthMetadataRouter`, and `mcpAuth.resourceMetadataUrl` provides the RFC 9728 metadata URL for the `WWW-Authenticate` challenge.
- New `getAuthInfo(context)` helper reads the verified `McpAuthInfo` (with guaranteed `issuer`, `subject`, and `claims`) from MCP request handler contexts.

Breaking changes:

- Requires `@modelcontextprotocol/server@^2` as a peer dependency; support for MCP SDK v1 (`@modelcontextprotocol/sdk`) is removed.
- The Express-specific APIs are removed: `bearerAuth()`, `protectedResourceMetadataRouter()`, `delegatedRouter()`, and the legacy `authorization server` mode. Use the SDK's `requireBearerAuth` and metadata helpers (or `@modelcontextprotocol/express`) instead.
- The custom verify-function mode and `getTokenVerifier()` are removed; JWT verification via the trusted server's JWKS is the only built-in mode.
- The `protectedResources` array is replaced by a singular `resource` + `authorizationServer` config; multi-resource deployments create multiple instances.
- Authorization server metadata now stays in wire format (snake_case), typed with the SDK's `OAuthMetadata`; the camelCase metadata types and transforms are removed.
- Audience (`aud`) validation is now ON by default (expecting the `resource` identifier); set `audience: false` for providers that do not include an `aud` claim.
- Access tokens without a `sub` claim are now rejected (`subject` is guaranteed on `McpAuthInfo`, per RFC 9068).
- Token verification failures now throw the SDK's `OAuthError` (mapped to `401` by the SDK bearer-auth helpers); `MCPAuthBearerAuthError` and `MCPAuthTokenVerificationError` are removed.
- The package is now ESM-only and requires Node.js >= 20.
