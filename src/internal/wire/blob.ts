/**
 * Blob token wire format (version 0x01).
 *
 * Password-mode (58 bytes header):
 *   [0]      version        = 0x01
 *   [1]      algorithm      0x01=aes-256-gcm, 0x02=chacha20-poly1305
 *   [2]      kdf            0x01=argon2id, 0x02=pbkdf2-sha256
 *   [3..6]   argon2_mem_kb  uint32 LE
 *   [7..10]  argon2_iter    uint32 LE
 *   [11..12] argon2_par     uint16 LE
 *   [13]     argon2_outlen  uint8 = 32
 *   [14..29] salt           16 bytes
 *   [30..41] nonce          12 bytes
 *   [42..57] tag            16 bytes
 *   [58..]   ciphertext
 *   AAD = bytes [0..41]
 *
 * Raw-key-mode (33 bytes header):
 *   [0]      version        = 0x01
 *   [1]      algorithm
 *   [2]      kdf            = 0x00
 *   [3..4]   key_id         uint16 LE
 *   [5..16]  nonce          12 bytes
 *   [17..32] tag            16 bytes
 *   [33..]   ciphertext
 *   AAD = bytes [0..16]
 */
import { deriveKey as argon2DeriveKey } from '../kdf/argon2.js';
import { deriveKey as pbkdf2DeriveKey } from '../kdf/pbkdf2.js';
import { encrypt, decrypt, algorithmName } from '../aead.js';
import { generateNonce, generateSalt } from '../nonce.js';
import { CasketDecryptionError, CasketUnsupportedVersionError, CasketConfigurationError } from '../../errors.js';

const VERSION = 0x01;
const TAG_SIZE = 16;
const NONCE_SIZE = 12;
const SALT_SIZE = 16;

// Password-mode offsets
const PWD_CIPHERTEXT_OFFSET = 58;
const PWD_AAD_LENGTH = 42;

// Raw-key-mode offsets
const RAW_CIPHERTEXT_OFFSET = 33;
const RAW_AAD_LENGTH = 17;

export async function sealPassword(
  plaintext: Buffer,
  password: string,
  algorithmByte: number,
  kdfByte: number,
  memKiB: number,
  iterations: number,
  parallelism: number,
  saltOverride?: Buffer,
  nonceOverride?: Buffer,
): Promise<Buffer> {
  const salt = saltOverride ?? generateSalt(SALT_SIZE);
  const nonce = nonceOverride ?? generateNonce(NONCE_SIZE);

  let key: Buffer;
  if (kdfByte === 0x01) {
    key = await argon2DeriveKey(password, salt, memKiB, iterations, parallelism);
  } else {
    key = await pbkdf2DeriveKey(password, salt, iterations);
  }

  const token = Buffer.alloc(PWD_CIPHERTEXT_OFFSET + plaintext.length);
  token[0] = VERSION;
  token[1] = algorithmByte;
  token[2] = kdfByte;

  if (kdfByte === 0x01) { // Argon2id
    token.writeUInt32LE(memKiB, 3);
    token.writeUInt32LE(iterations, 7);
    token.writeUInt16LE(parallelism, 11);
    token[13] = 32;
  } else { // PBKDF2 — iterations at offset 3, rest zeros, outlen=32
    token.writeUInt32LE(iterations, 3);
    token.fill(0, 7, 13);
    token[13] = 32;
  }

  salt.copy(token, 14);
  nonce.copy(token, 30);

  const aad = token.subarray(0, PWD_AAD_LENGTH);
  const { ciphertext, tag } = encrypt(algorithmName(algorithmByte), key, nonce, plaintext, aad);
  tag.copy(token, 42);
  ciphertext.copy(token, PWD_CIPHERTEXT_OFFSET);

  return token;
}

export async function unsealPassword(token: Buffer, password: string): Promise<Buffer> {
  if (token.length < PWD_CIPHERTEXT_OFFSET)
    throw new CasketDecryptionError();
  if (token[0] !== VERSION)
    throw new CasketUnsupportedVersionError(token[0]);

  const algorithmByte = token[1];
  const kdfByte = token[2];
  if (token[13] !== 32)
    throw new CasketConfigurationError('Token has invalid key output length.');

  const salt = token.subarray(14, 30);
  const nonce = token.subarray(30, 42);
  const tag = token.subarray(42, 58);
  const ciphertext = token.subarray(PWD_CIPHERTEXT_OFFSET);
  const aad = token.subarray(0, PWD_AAD_LENGTH);

  let key: Buffer;
  if (kdfByte === 0x01) {
    const memKiB = token.readUInt32LE(3);
    const iter = token.readUInt32LE(7);
    const par = token.readUInt16LE(11);
    key = await argon2DeriveKey(password, salt as Buffer, memKiB, iter, par);
  } else if (kdfByte === 0x02) {
    const iter = token.readUInt32LE(3);
    key = await pbkdf2DeriveKey(password, salt as Buffer, iter);
  } else {
    throw new CasketDecryptionError();
  }

  return decrypt(algorithmName(algorithmByte), key, nonce as Buffer, ciphertext as Buffer, aad as Buffer, tag as Buffer);
}

export function sealRawKey(
  plaintext: Buffer,
  key: Buffer,
  algorithmByte: number,
  keyId: number,
  nonceOverride?: Buffer,
): Buffer {
  const nonce = nonceOverride ?? generateNonce(NONCE_SIZE);
  const token = Buffer.alloc(RAW_CIPHERTEXT_OFFSET + plaintext.length);
  token[0] = VERSION;
  token[1] = algorithmByte;
  token[2] = 0x00; // kdf = None
  token.writeUInt16LE(keyId, 3);
  nonce.copy(token, 5);

  const aad = token.subarray(0, RAW_AAD_LENGTH);
  const { ciphertext, tag } = encrypt(algorithmName(algorithmByte), key, nonce, plaintext, aad);
  tag.copy(token, 17);
  ciphertext.copy(token, RAW_CIPHERTEXT_OFFSET);

  return token;
}

export function unsealRawKey(token: Buffer, key: Buffer): Buffer {
  if (token.length < RAW_CIPHERTEXT_OFFSET)
    throw new CasketDecryptionError();
  if (token[0] !== VERSION)
    throw new CasketUnsupportedVersionError(token[0]);

  const algorithmByte = token[1];
  const nonce = token.subarray(5, 17);
  const tag = token.subarray(17, 33);
  const ciphertext = token.subarray(RAW_CIPHERTEXT_OFFSET);
  const aad = token.subarray(0, RAW_AAD_LENGTH);

  return decrypt(algorithmName(algorithmByte), key, nonce as Buffer, ciphertext as Buffer, aad as Buffer, tag as Buffer);
}

export function peekHeader(token: Buffer): { kdfByte: number; keyId: number } {
  if (token.length < 5) throw new CasketDecryptionError();
  const kdfByte = token[2];
  const keyId = kdfByte === 0x00 ? token.readUInt16LE(3) : 0;
  return { kdfByte, keyId };
}
