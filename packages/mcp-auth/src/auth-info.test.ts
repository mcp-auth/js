import { type AuthInfo, type BaseContext } from '@modelcontextprotocol/server';
import { describe, expect, it } from 'vitest';

import { getAuthInfo, isMcpAuthInfo, type McpAuthInfo } from './auth-info.js';
import { MCPAuthError } from './errors.js';
import { matchError } from './test-utils.js';

const mcpAuthInfo: McpAuthInfo = {
  token: 'token',
  issuer: 'https://auth.example.com',
  subject: 'user-1',
  clientId: 'client-1',
  scopes: ['read'],
  expiresAt: 1_234_567_890,
  claims: { iss: 'https://auth.example.com', sub: 'user-1' },
};

const plainAuthInfo: AuthInfo = {
  token: 'token',
  clientId: 'client-1',
  scopes: [],
};

/* Construct a minimal context for testing; the full `mcpReq` shape is irrelevant here. */
const createContext = (http?: { authInfo?: AuthInfo }): BaseContext => {
  const context: Pick<BaseContext, 'http'> = { ...(http && { http }) };
  return context as BaseContext;
};

describe('isMcpAuthInfo', () => {
  it('should return true for auth info produced by mcp-auth', () => {
    expect(isMcpAuthInfo(mcpAuthInfo)).toBe(true);
  });

  it('should return false for auth info without the mcp-auth guarantees', () => {
    expect(isMcpAuthInfo(plainAuthInfo)).toBe(false);
    expect(isMcpAuthInfo({ ...mcpAuthInfo, claims: undefined } as AuthInfo)).toBe(false);
  });
});

describe('getAuthInfo', () => {
  it('should return the auth info from the context', () => {
    expect(getAuthInfo(createContext({ authInfo: mcpAuthInfo }))).toBe(mcpAuthInfo);
  });

  it('should throw if the context has no HTTP information', () => {
    expect(() => getAuthInfo(createContext())).toThrowError(MCPAuthError);
    expect(() => getAuthInfo(createContext())).toThrowError(
      matchError('MCPAuthError', 'missing_auth_info')
    );
  });

  it('should throw if the context has no auth info', () => {
    expect(() => getAuthInfo(createContext({}))).toThrowError(
      matchError('MCPAuthError', 'missing_auth_info')
    );
  });

  it('should throw if the auth info was not produced by mcp-auth', () => {
    expect(() => getAuthInfo(createContext({ authInfo: plainAuthInfo }))).toThrowError(
      matchError('MCPAuthError', 'invalid_auth_info')
    );
  });
});
