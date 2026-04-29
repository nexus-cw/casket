import { describe, it, expect } from '@jest/globals';
import { Channel, ChannelPairError, ChannelVerifyError, ChannelDecryptError } from '../src/channel.js';
import type { ChannelStorage, DhAlgorithm } from '../src/channel.js';

function makeStorage(): ChannelStorage {
  const store = new Map<string, string>();
  return {
    get: async (k) => store.get(k) ?? null,
    put: async (k, v) => { store.set(k, v); },
    delete: async (k) => { store.delete(k); },
  };
}

async function makePairedChannels(alg: DhAlgorithm = 'P-256') {
  const storA = makeStorage();
  const storB = makeStorage();
  const chA = await Channel.load('nexus-a', storA, alg);
  const chB = await Channel.load('nexus-b', storB, alg);
  const tokenA = chA.makePairingToken('https://relay-a.workers.dev');
  const tokenB = chB.makePairingToken('https://relay-b.workers.dev');
  const pairedA = await chA.pair(tokenB);
  const pairedB = await chB.pair(tokenA);
  return { chA, chB, storA, storB, pairedA, pairedB };
}

describe('Channel', () => {
  it('generates Ed25519 and P-256 keypairs on first load (default)', async () => {
    const storage = makeStorage();
    const ch = await Channel.load('nexus-a', storage);
    expect(ch.publicKeyBytes().length).toBe(32);
    expect(ch.publicKeyB64u()).toMatch(/^[A-Za-z0-9_-]+$/);
    // P-256 uncompressed = 65 bytes
    expect(ch.dhPublicKeyBytes().length).toBe(65);
    expect(ch.dhPublicKeyB64u()).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(ch.dhAlg()).toBe('P-256');
  });

  it('generates X25519 keypair when requested', async () => {
    const storage = makeStorage();
    const ch = await Channel.load('nexus-a', storage, 'X25519');
    expect(ch.publicKeyBytes().length).toBe(32);
    // X25519 raw public key = 32 bytes
    expect(ch.dhPublicKeyBytes().length).toBe(32);
    expect(ch.dhAlg()).toBe('X25519');
  });

  it('reloads the same keypairs from storage (P-256)', async () => {
    const storage = makeStorage();
    const ch1 = await Channel.load('nexus-a', storage);
    const pub1   = ch1.publicKeyB64u();
    const dhPub1 = ch1.dhPublicKeyB64u();

    const ch2 = await Channel.load('nexus-a', storage);
    expect(ch2.publicKeyB64u()).toBe(pub1);
    expect(ch2.dhPublicKeyB64u()).toBe(dhPub1);
    expect(ch2.dhAlg()).toBe('P-256');
  });

  it('reloads the same keypairs from storage (X25519)', async () => {
    const storage = makeStorage();
    const ch1 = await Channel.load('nexus-a', storage, 'X25519');
    const pub1   = ch1.publicKeyB64u();
    const dhPub1 = ch1.dhPublicKeyB64u();

    // dhAlgorithm arg is ignored on reload — stored alg wins
    const ch2 = await Channel.load('nexus-a', storage, 'P-256');
    expect(ch2.publicKeyB64u()).toBe(pub1);
    expect(ch2.dhPublicKeyB64u()).toBe(dhPub1);
    expect(ch2.dhAlg()).toBe('X25519');
  });

  it('makePairingToken includes both pubkeys and dh_alg', async () => {
    const storage = makeStorage();
    const ch = await Channel.load('nexus-a', storage);
    const token = ch.makePairingToken('https://relay-a.workers.dev');

    expect(token.v).toBe(1);
    expect(token.nexus_id).toBe('nexus-a');
    expect(token.sig_alg).toBe('ed25519');
    expect(token.dh_alg).toBe('P-256');
    expect(token.pubkey).toBe(ch.publicKeyB64u());
    expect(token.dh_pubkey).toBe(ch.dhPublicKeyB64u());
    expect(token.endpoint).toBe('https://relay-a.workers.dev');
    expect(token.nonce.length).toBeGreaterThan(0);
    expect(token.ts).toBeGreaterThan(0);
  });

  it('makePairingToken carries X25519 dh_alg when channel uses X25519', async () => {
    const ch = await Channel.load('nexus-a', makeStorage(), 'X25519');
    const token = ch.makePairingToken('https://relay-a.workers.dev');
    expect(token.dh_alg).toBe('X25519');
  });

  describe('pair()', () => {
    it('produces a PairedChannel with a consistent path ID', async () => {
      const { pairedA, pairedB } = await makePairedChannels();
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

    it('rejects tokens with wrong Ed25519 pubkey length', async () => {
      const storA = makeStorage();
      const chA = await Channel.load('nexus-a', storA);
      const badToken = {
        v: 1 as const,
        nexus_id: 'nexus-b',
        sig_alg: 'ed25519' as const,
        dh_alg: 'P-256' as const,
        pubkey: 'aGVsbG8',  // "hello" — not 32 bytes
        dh_pubkey: 'aGVsbG8',
        endpoint: 'https://x.workers.dev',
        nonce: 'abc',
        ts: Math.floor(Date.now() / 1000),
      };
      await expect(chA.pair(badToken)).rejects.toThrow(ChannelPairError);
    });

    it('rejects a token when dh_alg mismatches the local channel', async () => {
      const chA = await Channel.load('nexus-a', makeStorage(), 'P-256');
      const chB = await Channel.load('nexus-b', makeStorage(), 'X25519');
      const tokenB = chB.makePairingToken('https://relay-b.workers.dev');
      await expect(chA.pair(tokenB)).rejects.toThrow(ChannelPairError);
    });
  });

  describe('getPaired()', () => {
    it('returns null for unknown peer', async () => {
      const storage = makeStorage();
      const ch = await Channel.load('nexus-a', storage);
      expect(await ch.getPaired('nexus-b')).toBeNull();
    });

    it('returns a PairedChannel with the same pathId after pairing', async () => {
      const { chA, pairedA } = await makePairedChannels();
      const reloaded = await chA.getPaired('nexus-b');
      expect(reloaded).not.toBeNull();
      expect(reloaded!.pathId()).toBe(pairedA.pathId());
    });
  });

  describe('revoke()', () => {
    it('removes peer so getPaired returns null', async () => {
      const { chA } = await makePairedChannels();
      await chA.revoke('nexus-b');
      expect(await chA.getPaired('nexus-b')).toBeNull();
    });
  });

  describe('sign() / verify()', () => {
    it('signs and verifies canonical envelope bytes', async () => {
      const { pairedA, pairedB } = await makePairedChannels();
      const envelope = new TextEncoder().encode(JSON.stringify({
        method: 'POST', path: '/mailbox/nxc_abc',
        origin_nexus: 'nexus-a', dest_nexus: 'nexus-b',
        msg_id: '01952c00-0000-7000-0000-000000000001',
        ts: 1713480000, body_sha256: 'abc123', kind: 'proposal', in_reply_to: null,
      }));

      const sig = await pairedA.sign(envelope);
      await expect(pairedB.verify(sig, envelope)).resolves.toBeUndefined();
    });

    it('verify throws on tampered envelope', async () => {
      const { pairedA, pairedB } = await makePairedChannels();
      const sig = await pairedA.sign(new TextEncoder().encode('{"msg_id":"abc"}'));
      await expect(
        pairedB.verify(sig, new TextEncoder().encode('{"msg_id":"xyz"}'))
      ).rejects.toThrow(ChannelVerifyError);
    });

    it('verify throws on bad signature', async () => {
      const { pairedB } = await makePairedChannels();
      const badSig = 'A'.repeat(86);
      await expect(
        pairedB.verify(badSig, new TextEncoder().encode('hello'))
      ).rejects.toThrow(ChannelVerifyError);
    });
  });

  describe('encryptBody() / decryptBody()', () => {
    it('round-trips plaintext through the shared key', async () => {
      const { pairedA, pairedB } = await makePairedChannels();
      const plaintext = new TextEncoder().encode('Hello, @keel-nexus — here is the spec proposal.');
      const ciphertext = await pairedA.encryptBody(plaintext);
      const recovered  = await pairedB.decryptBody(ciphertext);
      expect(new TextDecoder().decode(recovered)).toBe('Hello, @keel-nexus — here is the spec proposal.');
    });

    it('decryption works in both directions (shared key is symmetric)', async () => {
      const { pairedA, pairedB } = await makePairedChannels();
      const msg = new TextEncoder().encode('reply from B');
      const ct = await pairedB.encryptBody(msg);
      const pt = await pairedA.decryptBody(ct);
      expect(new TextDecoder().decode(pt)).toBe('reply from B');
    });

    it('each encryption produces a different ciphertext (random nonce)', async () => {
      const { pairedA } = await makePairedChannels();
      const pt = new TextEncoder().encode('same message');
      const ct1 = await pairedA.encryptBody(pt);
      const ct2 = await pairedA.encryptBody(pt);
      expect(ct1).not.toBe(ct2);
    });

    it('decryption fails on tampered ciphertext', async () => {
      const { pairedA, pairedB } = await makePairedChannels();
      const ct = await pairedA.encryptBody(new TextEncoder().encode('secret'));
      const blob = Buffer.from(ct.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
      // Flip a byte in the ciphertext region (after 12-byte nonce)
      blob[15] ^= 0xff;
      const tampered = blob.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      await expect(pairedB.decryptBody(tampered)).rejects.toThrow(ChannelDecryptError);
    });

    it('decryption fails when wrong channel tries to decrypt', async () => {
      const { pairedA } = await makePairedChannels();
      // Third frame — different shared key
      const storC = makeStorage();
      const storA2 = makeStorage();
      const chC  = await Channel.load('nexus-c', storC);
      const chA2 = await Channel.load('nexus-a-2', storA2);
      const tokenC  = chC.makePairingToken('https://relay-c.workers.dev');
      const tokenA2 = chA2.makePairingToken('https://relay-a2.workers.dev');
      const pairedC = await chC.pair(tokenA2);

      const ct = await pairedA.encryptBody(new TextEncoder().encode('top secret'));
      await expect(pairedC.decryptBody(ct)).rejects.toThrow(ChannelDecryptError);
    });

    it('respects AAD — decryption fails if AAD does not match', async () => {
      const { pairedA, pairedB } = await makePairedChannels();
      const aadA = new TextEncoder().encode('envelope-header-bytes');
      const aadB = new TextEncoder().encode('different-header-bytes');
      const ct = await pairedA.encryptBody(new TextEncoder().encode('body'), aadA);
      await expect(pairedB.decryptBody(ct, aadB)).rejects.toThrow(ChannelDecryptError);
    });

    it('decryptBody throws on input that is too short', async () => {
      const { pairedB } = await makePairedChannels();
      await expect(pairedB.decryptBody('YWJj')).rejects.toThrow(ChannelDecryptError);
    });

    it('X25519 round-trips plaintext through the shared key', async () => {
      const { pairedA, pairedB } = await makePairedChannels('X25519');
      const plaintext = new TextEncoder().encode('Hello via X25519');
      const ciphertext = await pairedA.encryptBody(plaintext);
      const recovered  = await pairedB.decryptBody(ciphertext);
      expect(new TextDecoder().decode(recovered)).toBe('Hello via X25519');
    });
  });
});
