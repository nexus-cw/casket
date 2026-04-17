import { randomBytes } from 'node:crypto';

export function generateNonce(length = 12): Buffer {
  return randomBytes(length);
}

export function generateSalt(length = 16): Buffer {
  return randomBytes(length);
}
