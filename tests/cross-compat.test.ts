import { describe, it, expect } from '@jest/globals';
import {
  sealPassword, unsealPassword, sealRawKey,
  unsealWithPassword, unsealWithKey,
  keySourceFromBuffer,
  base64UrlEncode,
} from '../src/index.js';

/**
 * Fixed-input test vectors shared with the C# package.
 * Both implementations must produce identical Base64Url tokens for the same inputs.
 */

// Vector 1: password-mode blob with Argon2id + AES-256-GCM
const V1_PASS = 'correct horse battery staple';
const V1_PLAIN = 'Hello, Casket!';
const V1_SALT = Buffer.from([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]);
const V1_NONCE = Buffer.from([0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b]);

// Vector 2: raw-key-mode blob with AES-256-GCM
const V2_KEY = Buffer.alloc(32, 0x42);
const V2_KEY_ID = 0x0001;
const V2_PLAIN = 'raw key test';
const V2_NONCE = Buffer.from([0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b]);

// Expected token from C# (recorded from CrossCompatTests output)
// AQEBAAABAAMAAAABACAAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobbqfird9JKJ0AMW7GOSZ3b1QIYVVOY9XblBEgZTOc
const EXPECTED_V1_TOKEN = 'AQEBAAABAAMAAAABACAAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobbqfird9JKJ0AMW7GOSZ3b1QIYVVOY9XblBEgZTOc';

describe('cross-compat vectors', () => {
  it('Vector1: password blob produces deterministic token', async () => {
    const token = await sealPassword(
      Buffer.from(V1_PLAIN, 'utf8'), V1_PASS,
      0x01, 0x01, // AES-256-GCM, Argon2id
      65536, 3, 1,
      V1_SALT, V1_NONCE,
    );
    const tokenStr = base64UrlEncode(token);
    console.log('[CrossCompat] Vector1 token:', tokenStr);

    // Header structure
    expect(token[0]).toBe(0x01); // version
    expect(token[1]).toBe(0x01); // AES-256-GCM
    expect(token[2]).toBe(0x01); // Argon2id
    expect(token.subarray(14, 30)).toEqual(V1_SALT);
    expect(token.subarray(30, 42)).toEqual(V1_NONCE);

    // Round-trip
    const decrypted = await unsealWithPassword(tokenStr, V1_PASS);
    expect(decrypted).toBe(V1_PLAIN);

    // Cross-language: must match C# output
    expect(tokenStr).toBe(EXPECTED_V1_TOKEN);
  });

  it('Vector2: raw key blob produces deterministic token', async () => {
    const token = sealRawKey(
      Buffer.from(V2_PLAIN, 'utf8'), V2_KEY,
      0x01, // AES-256-GCM
      V2_KEY_ID,
      V2_NONCE,
    );
    const tokenStr = base64UrlEncode(token);
    console.log('[CrossCompat] Vector2 token:', tokenStr);

    // Header structure
    expect(token[0]).toBe(0x01); // version
    expect(token[1]).toBe(0x01); // AES-256-GCM
    expect(token[2]).toBe(0x00); // raw key (kdf=None)
    expect(token[3]).toBe(0x01); // key_id low byte
    expect(token[4]).toBe(0x00); // key_id high byte
    expect(token.subarray(5, 17)).toEqual(V2_NONCE);

    // Round-trip
    const src = keySourceFromBuffer(V2_KEY, V2_KEY_ID);
    const decrypted = unsealWithKey(tokenStr, src);
    expect(decrypted).toBe(V2_PLAIN);
  });
});
