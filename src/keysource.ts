import { readFileSync } from 'node:fs';
import { decode } from './internal/base64url.js';
import { CasketConfigurationError } from './errors.js';

export interface CasketKeySource {
  getKey(): Buffer;
  keyId: number;
}

export interface AsyncCasketKeySource {
  getKey(): Promise<Buffer>;
  keyId: number;
}

function validateKey(buf: Buffer, source: string): Buffer {
  if (buf.length !== 32)
    throw new CasketConfigurationError(`Key source '${source}' decoded to ${buf.length} bytes; expected 32.`);
  return buf;
}

export function keySourceFromEnv(name = 'CASKET_KEY', keyId = 0): CasketKeySource {
  const value = process.env[name];
  if (!value)
    throw new CasketConfigurationError(`Environment variable '${name}' is not set.`);
  const key = validateKey(decode(value), name);
  return { getKey: () => key, keyId };
}

export function keySourceFromFile(path: string, keyId = 0): CasketKeySource {
  const value = readFileSync(path, 'utf8').trim();
  const key = validateKey(decode(value), path);
  return { getKey: () => key, keyId };
}

export function keySourceFromBuffer(key: Buffer, keyId = 0): CasketKeySource {
  if (key.length !== 32)
    throw new CasketConfigurationError(`Key must be exactly 32 bytes, got ${key.length}.`);
  return { getKey: () => key, keyId };
}
