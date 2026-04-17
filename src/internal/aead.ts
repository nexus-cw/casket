import { createCipheriv, createDecipheriv, CipherGCM, DecipherGCM } from 'node:crypto';
import { CasketDecryptionError } from '../errors.js';

const TAG_SIZE = 16;

export function encrypt(
  algorithm: 'aes-256-gcm' | 'chacha20-poly1305',
  key: Buffer,
  nonce: Buffer,
  plaintext: Buffer,
  aad: Buffer,
): { ciphertext: Buffer; tag: Buffer } {
  const cipher = createCipheriv(algorithm, key, nonce) as CipherGCM;
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { ciphertext, tag };
}

export function decrypt(
  algorithm: 'aes-256-gcm' | 'chacha20-poly1305',
  key: Buffer,
  nonce: Buffer,
  ciphertext: Buffer,
  aad: Buffer,
  tag: Buffer,
): Buffer {
  try {
    const decipher = createDecipheriv(algorithm, key, nonce) as DecipherGCM;
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new CasketDecryptionError();
  }
}

export function algorithmName(byte: number): 'aes-256-gcm' | 'chacha20-poly1305' {
  if (byte === 0x01) return 'aes-256-gcm';
  if (byte === 0x02) return 'chacha20-poly1305';
  throw new Error(`Unknown algorithm byte: 0x${byte.toString(16)}`);
}

export { TAG_SIZE };
