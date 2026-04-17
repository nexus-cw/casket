import { describe, it, expect } from '@jest/globals';
import {
  sealWithPassword, unsealWithPassword,
  sealWithKey, unsealWithKey,
  generateKey,
  keySourceFromBuffer,
  CasketDecryptionError,
} from '../src/index.js';

describe('seal/unseal', () => {
  it('password round-trip AES-256-GCM + Argon2id', async () => {
    const token = await sealWithPassword('Hello, World!', 'password');
    const result = await unsealWithPassword(token, 'password');
    expect(result).toBe('Hello, World!');
  });

  it('password round-trip ChaCha20-Poly1305', async () => {
    const token = await sealWithPassword('test', 'pw', { algorithm: 'chacha20-poly1305' });
    const result = await unsealWithPassword(token, 'pw');
    expect(result).toBe('test');
  });

  it('password round-trip PBKDF2', async () => {
    const token = await sealWithPassword('pbkdf2', 'pw', { kdf: 'pbkdf2-sha256', pbkdf2Iterations: 10000 });
    const result = await unsealWithPassword(token, 'pw');
    expect(result).toBe('pbkdf2');
  });

  it('raw key round-trip', () => {
    const key = Buffer.alloc(32, 0xAA);
    const src = keySourceFromBuffer(key, 1);
    const token = sealWithKey('raw key test', src);
    const result = unsealWithKey(token, src);
    expect(result).toBe('raw key test');
  });

  it('wrong password throws', async () => {
    const token = await sealWithPassword('secret', 'correct');
    await expect(unsealWithPassword(token, 'wrong')).rejects.toBeInstanceOf(CasketDecryptionError);
  });

  it('wrong key throws', () => {
    const key1 = Buffer.alloc(32, 0x01);
    const key2 = Buffer.alloc(32, 0x02);
    const src1 = keySourceFromBuffer(key1, 1);
    const src2 = keySourceFromBuffer(key2, 2);
    const token = sealWithKey('data', src1);
    expect(() => unsealWithKey(token, src2)).toThrow(CasketDecryptionError);
  });

  it('generateKey returns 43-char base64url', () => {
    const key = generateKey();
    expect(key).toHaveLength(43);
    expect(key).not.toContain('=');
    expect(key).not.toContain('+');
    expect(key).not.toContain('/');
  });

  it('empty plaintext round-trip', async () => {
    const token = await sealWithPassword('', 'pw', { kdf: 'pbkdf2-sha256', pbkdf2Iterations: 1000 });
    const result = await unsealWithPassword(token, 'pw');
    expect(result).toBe('');
  });

  it('unicode plaintext round-trip', async () => {
    const plaintext = 'こんにちは世界 🔐';
    const token = await sealWithPassword(plaintext, 'pw', { kdf: 'pbkdf2-sha256', pbkdf2Iterations: 1000 });
    const result = await unsealWithPassword(token, 'pw');
    expect(result).toBe(plaintext);
  });

  it('produces different token each call', async () => {
    const t1 = await sealWithPassword('same', 'same', { kdf: 'pbkdf2-sha256', pbkdf2Iterations: 1000 });
    const t2 = await sealWithPassword('same', 'same', { kdf: 'pbkdf2-sha256', pbkdf2Iterations: 1000 });
    expect(t1).not.toBe(t2);
  });
});
