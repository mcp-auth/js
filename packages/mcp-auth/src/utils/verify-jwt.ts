import { type VerifyAccessTokenFunction } from '../handlers/handle-bearer-auth';

export const verifyJwt: VerifyAccessTokenFunction = async (token) => {
  throw new Error('JWT verification is not implemented.');
};
