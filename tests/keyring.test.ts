import { describe, it, expect } from '@jest/globals';
import { CasketKeyRing, CasketKeyNotFoundError, CasketDecryptionError, keySourceFromBuffer, sealWithKey } from '../src/index.js';

describe('CasketKeyRing', () => {
  it('dispatches by key ID', () => {
    const key1 = Buffer.alloc(32, 0x01);
    const key2 = Buffer.alloc(32, 0x02);
    const src1 = keySourceFromBuffer(key1, 1);
    const src2 = keySourceFromBuffer(key2, 2);
    const token = sealWithKey('sealed with key1', src1);
    const ring = new CasketKeyRing().add(src1).add(src2);
    expect(ring.unseal(token)).toBe('sealed with key1');
  });

  it('falls back on anonymous key', () => {
    const key = Buffer.alloc(32, 0xAA);
    const anonSrc = keySourceFromBuffer(key, 0); // anonymous
    const token = sealWithKey('anon', anonSrc);
    const ringSrc = keySourceFromBuffer(key, 1);
    const ring = new CasketKeyRing().add(ringSrc);
    expect(ring.unseal(token)).toBe('anon');
  });

  it('throws if key not registered', () => {
    const key = Buffer.alloc(32, 0x01);
    const src = keySourceFromBuffer(key, 1);
    const token = sealWithKey('data', src);
    const otherKey = Buffer.alloc(32, 0x02);
    const ring = new CasketKeyRing().add(keySourceFromBuffer(otherKey, 2));
    expect(() => ring.unseal(token)).toThrow(CasketKeyNotFoundError);
  });

  it('rejects duplicate key ID', () => {
    const key = Buffer.alloc(32, 0x01);
    const src1 = keySourceFromBuffer(key, 1);
    const src2 = keySourceFromBuffer(key, 1);
    const ring = new CasketKeyRing().add(src1);
    expect(() => ring.add(src2)).toThrow();
  });
});
