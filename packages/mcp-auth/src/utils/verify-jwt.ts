import { type VerifyAccessTokenFunction } from '../handlers/handle-bearer-auth.js';

export const verifyJwt: VerifyAccessTokenFunction = async (token) => {
  throw new Error('JWT verification is not implemented.');
};
