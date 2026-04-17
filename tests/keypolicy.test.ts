import { describe, it, expect } from '@jest/globals';
import { CasketKeyPolicy, CasketKeyLimitExceededError, keySourceFromBuffer, sealWithKey } from '../src/index.js';

describe('CasketKeyPolicy', () => {
  it('tracks seal count', () => {
    const policy = new CasketKeyPolicy({ hardLimit: 10n });
    const key = Buffer.alloc(32, 0x01);
    const src = keySourceFromBuffer(key, 1);
    sealWithKey('a', src, { keyPolicy: policy });
    sealWithKey('b', src, { keyPolicy: policy });
    expect(policy.sealCount).toBe(2n);
  });

  it('throws at hard limit', () => {
    const policy = new CasketKeyPolicy({ hardLimit: 2n });
    const key = Buffer.alloc(32, 0x01);
    const src = keySourceFromBuffer(key, 1);
    sealWithKey('a', src, { keyPolicy: policy });
    sealWithKey('b', src, { keyPolicy: policy });
    expect(() => sealWithKey('c', src, { keyPolicy: policy })).toThrow(CasketKeyLimitExceededError);
  });

  it('invokes warn callback', () => {
    let warned = false;
    const policy = new CasketKeyPolicy({
      hardLimit: 5n,
      warnThreshold: 2n,
      onApproachingLimit: () => { warned = true; },
    });
    const key = Buffer.alloc(32, 0x01);
    const src = keySourceFromBuffer(key, 1);
    sealWithKey('a', src, { keyPolicy: policy });
    expect(warned).toBe(false);
    sealWithKey('b', src, { keyPolicy: policy });
    expect(warned).toBe(true);
  });

  it('reset clears count', () => {
    const policy = new CasketKeyPolicy({ hardLimit: 2n });
    const key = Buffer.alloc(32, 0x01);
    const src = keySourceFromBuffer(key, 1);
    sealWithKey('a', src, { keyPolicy: policy });
    sealWithKey('b', src, { keyPolicy: policy });
    policy.reset();
    expect(policy.sealCount).toBe(0n);
    sealWithKey('c', src, { keyPolicy: policy }); // should not throw
  });
});
