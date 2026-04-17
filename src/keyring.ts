import { CasketKeySource, AsyncCasketKeySource } from './keysource.js';
import { unsealRawKey, peekHeader } from './internal/wire/blob.js';
import { decode } from './internal/base64url.js';
import { CasketDecryptionError, CasketKeyNotFoundError } from './errors.js';

export class CasketKeyRing {
  private syncSources: CasketKeySource[] = [];
  private asyncSources: AsyncCasketKeySource[] = [];
  private keyIds: number[] = [];

  add(source: CasketKeySource | AsyncCasketKeySource): this {
    if (source.keyId === 0)
      throw new Error('KeyId must be non-zero when registering with a CasketKeyRing.');
    if (this.keyIds.includes(source.keyId))
      throw new Error(`Key ID 0x${source.keyId.toString(16).padStart(4,'0')} is already registered.`);
    this.keyIds.push(source.keyId);
    if ('getKey' in source && typeof (source as CasketKeySource).getKey() !== 'object') {
      this.asyncSources.push(source as AsyncCasketKeySource);
    } else {
      // Distinguish sync vs async by checking return type
      const result = (source as CasketKeySource).getKey();
      if (result instanceof Promise) {
        this.asyncSources.push(source as unknown as AsyncCasketKeySource);
      } else {
        this.syncSources.push(source as CasketKeySource);
      }
    }
    return this;
  }

  get registeredKeyIds(): number[] { return [...this.keyIds]; }

  unseal(token: string): string {
    const tokenBuf = decode(token);
    const { kdfByte, keyId } = peekHeader(tokenBuf);
    if (kdfByte !== 0x00) throw new CasketDecryptionError();

    if (keyId !== 0) {
      const src = this.syncSources.find(s => s.keyId === keyId);
      if (!src) throw new CasketKeyNotFoundError(keyId);
      return unsealRawKey(tokenBuf, src.getKey()).toString('utf8');
    }

    for (const src of this.syncSources) {
      try { return unsealRawKey(tokenBuf, src.getKey()).toString('utf8'); }
      catch { /* try next */ }
    }
    throw new CasketKeyNotFoundError(0);
  }

  async unsealAsync(token: string): Promise<string> {
    const tokenBuf = decode(token);
    const { kdfByte, keyId } = peekHeader(tokenBuf);
    if (kdfByte !== 0x00) throw new CasketDecryptionError();

    if (keyId !== 0) {
      const asyncSrc = this.asyncSources.find(s => s.keyId === keyId);
      if (asyncSrc) return unsealRawKey(tokenBuf, await asyncSrc.getKey()).toString('utf8');
      const syncSrc = this.syncSources.find(s => s.keyId === keyId);
      if (syncSrc) return unsealRawKey(tokenBuf, syncSrc.getKey()).toString('utf8');
      throw new CasketKeyNotFoundError(keyId);
    }

    for (const src of this.syncSources) {
      try { return unsealRawKey(tokenBuf, src.getKey()).toString('utf8'); }
      catch { /* try next */ }
    }
    for (const src of this.asyncSources) {
      try { return unsealRawKey(tokenBuf, await src.getKey()).toString('utf8'); }
      catch { /* try next */ }
    }
    throw new CasketKeyNotFoundError(0);
  }
}
