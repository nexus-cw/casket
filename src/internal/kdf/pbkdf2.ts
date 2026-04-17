import { pbkdf2 } from 'node:crypto';

export function deriveKey(
  password: string,
  salt: Buffer,
  iterations: number,
  hashLength = 32,
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    pbkdf2(password, salt, iterations, hashLength, 'sha256', (err, key) => {
      if (err) reject(err); else resolve(key);
    });
  });
}
