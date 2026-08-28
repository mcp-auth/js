import { type AuthInfo, type BaseContext } from '@modelcontextprotocol/server';
import { type JWTPayload } from 'jose';

import { MCPAuthError } from './errors.js';

/**
 * The MCP SDK's `AuthInfo`, extended with the guarantees mcp-auth provides after successful JWT
 * verification:
 *
 * - `issuer`: the verified `iss` claim — always the configured trusted authorization server
 * - `subject`: the verified `sub` claim, identifying the end user or client (required, per
 *   RFC 9068)
 * - `claims`: the full verified JWT payload for access to any custom claims
 */
export type McpAuthInfo = AuthInfo & {
  /** The issuer of the token (the `iss` claim). */
  issuer: string;
  /** The subject of the token (the `sub` claim), typically the user ID. */
  subject: string;
  /** The full verified JWT payload. */
  claims: JWTPayload;
};

/**
 * Checks whether an `AuthInfo` object carries the mcp-auth guarantees ({@link McpAuthInfo}),
 * i.e. it was produced by `MCPAuth#verifyAccessToken`.
 */
export const isMcpAuthInfo = (info: AuthInfo): info is McpAuthInfo =>
  'issuer' in info &&
  typeof info.issuer === 'string' &&
  'subject' in info &&
  typeof info.subject === 'string' &&
  'claims' in info &&
  typeof info.claims === 'object' &&
  info.claims !== null;

export type GetAuthInfoOptions = {
  /**
   * Scopes the access token must include, for per-tool authorization on top of the
   * endpoint-level `requiredScopes` of the SDK's `requireBearerAuth`.
   *
   * When any are missing, an {@link MCPAuthError} with code `'missing_required_scopes'` is
   * thrown. The MCP SDK converts errors thrown in tool callbacks into tool error results
   * (`isError: true`), so the model receives a graceful `insufficient_scope: ...` refusal
   * instead of a failed request.
   */
  requiredScopes?: string[];
};

/**
 * Extracts the verified {@link McpAuthInfo} from an MCP request handler context (e.g. a tool
 * callback's second argument), optionally enforcing per-tool scopes.
 *
 * The bearer-auth middleware guarantees the auth info is present on every authenticated HTTP
 * request, so a missing value indicates a wiring problem — for example, the MCP endpoint is not
 * protected by `requireBearerAuth`, or a different token verifier than `MCPAuth` is in use.
 *
 * @example
 * ```ts
 * import { getAuthInfo } from 'mcp-auth';
 *
 * server.registerTool('whoami', { description: 'Get the current user' }, (ctx) => {
 *   const { subject, claims } = getAuthInfo(ctx);
 *   return { content: [{ type: 'text', text: JSON.stringify({ subject, claims }) }] };
 * });
 *
 * server.registerTool('purge-notes', { description: 'Delete every note' }, (ctx) => {
 *   // Throws unless the token has the `notes:write` scope; the SDK surfaces the error to the
 *   // model as a tool error result.
 *   const { subject } = getAuthInfo(ctx, { requiredScopes: ['notes:write'] });
 *   // ...
 * });
 * ```
 *
 * @param context The request handler context provided by the MCP SDK.
 * @param options Optional per-tool authorization requirements.
 * @returns The verified auth info.
 * @throws {MCPAuthError} if the context has no auth info, the auth info was not produced by
 * `MCPAuth#verifyAccessToken`, or a required scope is missing.
 */
export const getAuthInfo = (context: BaseContext, options?: GetAuthInfoOptions): McpAuthInfo => {
  const authInfo = context.http?.authInfo;

  if (!authInfo) {
    throw new MCPAuthError(
      'missing_auth_info',
      'No auth info found in the request context. Ensure the MCP endpoint is protected by `requireBearerAuth` with an `MCPAuth` instance as the verifier.'
    );
  }

  if (!isMcpAuthInfo(authInfo)) {
    throw new MCPAuthError(
      'invalid_auth_info',
      'The auth info in the request context was not produced by mcp-auth. Ensure the `MCPAuth` instance is used as the token verifier.'
    );
  }

  const missingScopes =
    options?.requiredScopes?.filter((scope) => !authInfo.scopes.includes(scope)) ?? [];

  if (missingScopes.length > 0) {
    throw new MCPAuthError(
      'missing_required_scopes',
      `insufficient_scope: the access token is missing the required scopes (${missingScopes.join(', ')}).`
    );
  }

  return authInfo;
};
