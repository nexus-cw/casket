import { describe, it, expect, beforeEach } from '@jest/globals';
import { Channel, ChannelPairError, ChannelVerifyError } from '../src/channel.js';
import type { ChannelStorage } from '../src/channel.js';

function makeStorage(): ChannelStorage {
  const store = new Map<string, string>();
  return {
    get: async (k) => store.get(k) ?? null,
    put: async (k, v) => { store.set(k, v); },
    delete: async (k) => { store.delete(k); },
  };
}

describe('Channel', () => {
  it('generates a keypair on first load', async () => {
    const storage = makeStorage();
    const ch = await Channel.load('nexus-a', storage);
    expect(ch.publicKeyBytes().length).toBe(32);
    expect(ch.publicKeyB64u()).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it('reloads the same keypair from storage', async () => {
    const storage = makeStorage();
    const ch1 = await Channel.load('nexus-a', storage);
    const pub1 = ch1.publicKeyB64u();

    const ch2 = await Channel.load('nexus-a', storage);
    expect(ch2.publicKeyB64u()).toBe(pub1);
  });

  it('makePairingToken returns a well-formed token', async () => {
    const storage = makeStorage();
    const ch = await Channel.load('nexus-a', storage);
    const token = ch.makePairingToken('https://relay.nexus-a.workers.dev');

    expect(token.v).toBe(1);
    expect(token.nexus_id).toBe('nexus-a');
    expect(token.pubkey).toBe(ch.publicKeyB64u());
    expect(token.endpoint).toBe('https://relay.nexus-a.workers.dev');
    expect(token.nonce.length).toBeGreaterThan(0);
    expect(token.ts).toBeGreaterThan(0);
  });

  describe('pair()', () => {
    it('produces a PairedChannel with a consistent path ID', async () => {
      const storA = makeStorage();
      const storB = makeStorage();
      const chA = await Channel.load('nexus-a', storA);
      const chB = await Channel.load('nexus-b', storB);

      const tokenA = chA.makePairingToken('https://relay-a.workers.dev');
      const tokenB = chB.makePairingToken('https://relay-b.workers.dev');

      const pairedA = await chA.pair(tokenB);
      const pairedB = await chB.pair(tokenA);

      // Both sides must compute the same path ID.
      expect(pairedA.pathId()).toBe(pairedB.pathId());
      expect(pairedA.pathId()).toMatch(/^nxc_[A-Za-z0-9_-]+$/);
    });

    it('path ID is symmetric regardless of who calls pair() first', async () => {
      const storA = makeStorage();
      const storB = makeStorage();
      const chA = await Channel.load('nexus-a', storA);
      const chB = await Channel.load('nexus-b', storB);

      const tokenA = chA.makePairingToken('https://relay-a.workers.dev');
      const tokenB = chB.makePairingToken('https://relay-b.workers.dev');

      const pairedB_first = await chB.pair(tokenA);
      const pairedA_first = await chA.pair(tokenB);

      expect(pairedA_first.pathId()).toBe(pairedB_first.pathId());
    });

    it('rejects tokens older than maxAgeSeconds', async () => {
      const storA = makeStorage();
      const storB = makeStorage();
      const chA = await Channel.load('nexus-a', storA);
      const chB = await Channel.load('nexus-b', storB);

      const staleToken = chB.makePairingToken('https://relay-b.workers.dev');
      staleToken.ts = Math.floor(Date.now() / 1000) - 9999;

      await expect(chA.pair(staleToken, 3600)).rejects.toThrow(ChannelPairError);
    });

    it('rejects tokens with invalid pubkey length', async () => {
      const storA = makeStorage();
      const chA = await Channel.load('nexus-a', storA);

      const badToken = {
        v: 1 as const,
        nexus_id: 'nexus-b',
        pubkey: 'aGVsbG8=',  // "hello" — not 32 bytes
        endpoint: 'https://x.workers.dev',
        nonce: 'abc',
        ts: Math.floor(Date.now() / 1000),
      };
      await expect(chA.pair(badToken)).rejects.toThrow(ChannelPairError);
    });
  });

  describe('getPaired()', () => {
    it('returns null for unknown peer', async () => {
      const storage = makeStorage();
      const ch = await Channel.load('nexus-a', storage);
      expect(await ch.getPaired('nexus-b')).toBeNull();
    });

    it('returns the PairedChannel after pairing', async () => {
      const storA = makeStorage();
      const storB = makeStorage();
      const chA = await Channel.load('nexus-a', storA);
      const chB = await Channel.load('nexus-b', storB);

      const tokenB = chB.makePairingToken('https://relay-b.workers.dev');
      const paired = await chA.pair(tokenB);
      const reloaded = await chA.getPaired('nexus-b');

      expect(reloaded).not.toBeNull();
      expect(reloaded!.pathId()).toBe(paired.pathId());
    });
  });

  describe('revoke()', () => {
    it('removes peer so getPaired returns null', async () => {
      const storA = makeStorage();
      const storB = makeStorage();
      const chA = await Channel.load('nexus-a', storA);
      const chB = await Channel.load('nexus-b', storB);

      const tokenB = chB.makePairingToken('https://relay-b.workers.dev');
      await chA.pair(tokenB);
      await chA.revoke('nexus-b');

      expect(await chA.getPaired('nexus-b')).toBeNull();
    });
  });

  describe('sign() / verify()', () => {
    it('signs and verifies canonical envelope bytes', async () => {
      const storA = makeStorage();
      const storB = makeStorage();
      const chA = await Channel.load('nexus-a', storA);
      const chB = await Channel.load('nexus-b', storB);

      const tokenA = chA.makePairingToken('https://relay-a.workers.dev');
      const tokenB = chB.makePairingToken('https://relay-b.workers.dev');
      const pairedA = await chA.pair(tokenB);
      const pairedB = await chB.pair(tokenA);

      const envelope = new TextEncoder().encode(JSON.stringify({
        method: 'POST',
        path: '/relay/inbound',
        origin_nexus: 'nexus-a',
        dest_nexus: 'nexus-b',
        msg_id: '01952c00-0000-7000-0000-000000000001',
        ts: 1713480000,
        body_sha256: 'abc123',
        kind: 'proposal',
        in_reply_to: null,
      }));

      const sig = await pairedA.sign(envelope);
      await expect(pairedB.verify(sig, envelope)).resolves.toBeUndefined();
    });

    it('verify throws on tampered envelope', async () => {
      const storA = makeStorage();
      const storB = makeStorage();
      const chA = await Channel.load('nexus-a', storA);
      const chB = await Channel.load('nexus-b', storB);

      const tokenA = chA.makePairingToken('https://relay-a.workers.dev');
      const tokenB = chB.makePairingToken('https://relay-b.workers.dev');
      const pairedA = await chA.pair(tokenB);
      const pairedB = await chB.pair(tokenA);

      const envelope = new TextEncoder().encode('{"msg_id":"abc"}');
      const sig = await pairedA.sign(envelope);

      const tampered = new TextEncoder().encode('{"msg_id":"xyz"}');
      await expect(pairedB.verify(sig, tampered)).rejects.toThrow(ChannelVerifyError);
    });

    it('verify throws on wrong signature', async () => {
      const storA = makeStorage();
      const storB = makeStorage();
      const chA = await Channel.load('nexus-a', storA);
      const chB = await Channel.load('nexus-b', storB);

      const tokenA = chA.makePairingToken('https://relay-a.workers.dev');
      const tokenB = chB.makePairingToken('https://relay-b.workers.dev');
      await chA.pair(tokenB);
      const pairedB = await chB.pair(tokenA);

      const data = new TextEncoder().encode('hello');
      const badSig = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
      await expect(pairedB.verify(badSig, data)).rejects.toThrow(ChannelVerifyError);
    });
  });
});
