import { type AuthServerConfig } from '../types/auth-server.js';

export const deduplicateAuthServers = (servers: AuthServerConfig[]): AuthServerConfig[] => {
  const uniqueServers = new Map<string, AuthServerConfig>();

  for (const server of servers) {
    const { issuer } = server.metadata;
    if (!uniqueServers.has(issuer)) {
      uniqueServers.set(issuer, server);
    }
  }

  return Array.from(uniqueServers.values());
};
