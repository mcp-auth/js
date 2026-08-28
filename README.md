# MCP Auth Node.js SDK

[![GitHub branch check runs](https://img.shields.io/github/check-runs/mcp-auth/js/master)](https://github.com/mcp-auth/js/actions?query=branch%3Amaster)
[![codecov](https://codecov.io/gh/mcp-auth/js/graph/badge.svg?token=JXZ4C50SCV)](https://codecov.io/gh/mcp-auth/js)
[![NPM version](https://img.shields.io/npm/v/mcp-auth)](https://www.npmjs.com/package/mcp-auth)
[![npm bundle size](https://img.shields.io/bundlephobia/minzip/mcp-auth)](https://bundlephobia.com/package/mcp-auth)
[![License](https://img.shields.io/npm/l/mcp-auth)](https://github.com/mcp-auth/js/blob/master/LICENSE)

The MCP spec [requires OAuth 2.1 and other RFCs](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) for auth. Instead of spending weeks on them, use MCP Auth to connect to a trusted provider with a few lines of code.

mcp-auth targets the current MCP specification (2025-11-25) and the MCP TypeScript SDK v2, implementing the spec's authorization requirements — RFC 9728 Protected Resource Metadata and RFC 8707 audience-bound token validation — for any OAuth 2.0 / OpenID Connect provider.

## Get started

### Is my provider supported?

Check out the [MCP-compatible providers](https://mcp-auth.dev/docs/provider-list) to see which providers are supported. It also includes a tool for real-time checking of provider compatibility.

### Installation

```bash
npm install mcp-auth
```

Or use your package manager of choice, such as `pnpm` or `yarn`.

Still on MCP SDK v1 (`@modelcontextprotocol/sdk`)? Stay on the 0.2 line — `npm install mcp-auth@0.2` — and see the [v0.2.0 code and samples](https://github.com/mcp-auth/js/tree/v0.2.0).

See [the documentation](https://mcp-auth.dev/docs) for the full guide.

## Join the discussion

Join the [MCP Auth org discussion](https://github.com/orgs/mcp-auth/discussions) to ask questions or share your feedback.
