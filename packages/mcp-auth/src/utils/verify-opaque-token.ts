import { type VerifyAccessTokenFunction } from '../handlers/handle-bearer-auth';

export const verifyOpaqueToken: VerifyAccessTokenFunction = async (token) => {
  throw new Error('Opaque token verification is not implemented.');
};
