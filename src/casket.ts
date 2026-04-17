import { randomBytes } from 'node:crypto';
import { sealPassword, unsealPassword, sealRawKey, unsealRawKey } from './internal/wire/blob.js';
import { encode, decode } from './internal/base64url.js';
import { CasketKeySource, AsyncCasketKeySource } from './keysource.js';
import { CasketKeyPolicy } from './keypolicy.js';

export type CasketAlgorithm = 'aes-256-gcm' | 'chacha20-poly1305';
export type CasketKdf = 'argon2id' | 'pbkdf2-sha256' | 'none';

export interface CasketOptions {
  algorithm?: CasketAlgorithm;
  kdf?: CasketKdf;
  argon2MemoryKiB?: number;
  argon2Iterations?: number;
  argon2Parallelism?: number;
  pbkdf2Iterations?: number;
  chunkSize?: number;
  keyPolicy?: CasketKeyPolicy;
}

function algorithmByte(alg: CasketAlgorithm): number {
  return alg === 'aes-256-gcm' ? 0x01 : 0x02;
}

function kdfByte(kdf: CasketKdf): number {
  if (kdf === 'argon2id') return 0x01;
  if (kdf === 'pbkdf2-sha256') return 0x02;
  return 0x00;
}

function resolveOptions(options?: CasketOptions) {
  return {
    algorithm: options?.algorithm ?? 'aes-256-gcm' as CasketAlgorithm,
    kdf: options?.kdf ?? 'argon2id' as CasketKdf,
    argon2MemoryKiB: options?.argon2MemoryKiB ?? 65536,
    argon2Iterations: options?.argon2Iterations ?? 3,
    argon2Parallelism: options?.argon2Parallelism ?? 1,
    pbkdf2Iterations: options?.pbkdf2Iterations ?? 600_000,
    chunkSize: options?.chunkSize ?? 65536,
    keyPolicy: options?.keyPolicy,
  };
}

// --- Password API ---

export async function sealWithPassword(plaintext: string, password: string, options?: CasketOptions): Promise<string> {
  const o = resolveOptions(options);
  o.keyPolicy?.recordSeal();
  const alg = algorithmByte(o.algorithm);
  const kdf = kdfByte(o.kdf);
  const token = await sealPassword(
    Buffer.from(plaintext, 'utf8'), password, alg, kdf,
    o.argon2MemoryKiB, o.argon2Iterations, o.argon2Parallelism,
  );
  return encode(token);
}

export async function unsealWithPassword(token: string, password: string): Promise<string> {
  const tokenBuf = decode(token);
  const plaintext = await unsealPassword(tokenBuf, password);
  return plaintext.toString('utf8');
}

// --- Raw key API (sync source) ---

export function sealWithKey(plaintext: string, keySource: CasketKeySource, options?: CasketOptions): string {
  const o = resolveOptions(options);
  o.keyPolicy?.recordSeal();
  const alg = algorithmByte(o.algorithm);
  const key = keySource.getKey();
  const token = sealRawKey(Buffer.from(plaintext, 'utf8'), key, alg, keySource.keyId);
  return encode(token);
}

export function unsealWithKey(token: string, keySource: CasketKeySource): string {
  const tokenBuf = decode(token);
  return unsealRawKey(tokenBuf, keySource.getKey()).toString('utf8');
}

// --- Raw key API (async source) ---

export async function sealWithKeyAsync(plaintext: string, keySource: AsyncCasketKeySource, options?: CasketOptions): Promise<string> {
  const o = resolveOptions(options);
  o.keyPolicy?.recordSeal();
  const alg = algorithmByte(o.algorithm);
  const key = await keySource.getKey();
  const token = sealRawKey(Buffer.from(plaintext, 'utf8'), key, alg, keySource.keyId);
  return encode(token);
}

export async function unsealWithKeyAsync(token: string, keySource: AsyncCasketKeySource): Promise<string> {
  const tokenBuf = decode(token);
  const key = await keySource.getKey();
  return unsealRawKey(tokenBuf, key).toString('utf8');
}

// --- Key generation ---

export function generateKey(): string {
  return encode(randomBytes(32));
}
