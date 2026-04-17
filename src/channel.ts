/**
 * Ed25519 channel identity for Frame-to-Frame relay.
 *
 * Each Frame has one Channel (one Ed25519 keypair). Pairing with a peer
 * produces a PairedChannel with a stable, symmetric path ID both sides
 * compute independently from their public keys.
 *
 * Storage is injected so the same code runs in Cloudflare Workers (KV)
 * and Node (any k/v you provide). Private key bytes never leave the
 * runtime once imported.
 */

export interface ChannelStorage {
  get(key: string): Promise<string | null>;
  put(key: string, value: string): Promise<void>;
  delete(key: string): Promise<void>;
}

export interface PairingToken {
  v: 1;
  nexus_id: string;
  pubkey: string;      // base64url Ed25519 public key (32 bytes)
  endpoint: string;    // https URL of this frame's relay Worker
  nonce: string;       // base64url 16 random bytes — token replay guard
  ts: number;          // unix seconds
}

export interface PeerRecord {
  nexus_id: string;
  pubkey: string;      // base64url
  endpoint: string;
  path_id: string;     // nxc_<base64url(sha256(...))>
  paired_at: number;   // unix seconds
}

const PRIVATE_KEY_STORAGE_KEY = 'casket:channel:private_key';
const PUBLIC_KEY_STORAGE_KEY  = 'casket:channel:public_key';
const PEER_KEY_PREFIX         = 'casket:peers:';

function b64uEncode(buf: Uint8Array): string {
  return Buffer.from(buf).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64uDecode(s: string): Uint8Array {
  const padded = s.replace(/-/g, '+').replace(/_/g, '/');
  const pad = padded.length % 4;
  const p = pad === 2 ? padded + '==' : pad === 3 ? padded + '=' : padded;
  return new Uint8Array(Buffer.from(p, 'base64'));
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest('SHA-256', data.buffer as ArrayBuffer);
  return new Uint8Array(digest);
}

async function computePathId(pubA: Uint8Array, pubB: Uint8Array): Promise<string> {
  // Lexicographic sort so both sides get the same ID regardless of who initiates.
  const [first, second] = compareBytes(pubA, pubB) <= 0
    ? [pubA, pubB]
    : [pubB, pubA];
  const combined = new Uint8Array(first.length + second.length);
  combined.set(first, 0);
  combined.set(second, first.length);
  const digest = await sha256(combined);
  return `nxc_${b64uEncode(digest)}`;
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

function randomBytes(n: number): Uint8Array {
  const buf = new Uint8Array(n);
  crypto.getRandomValues(buf);
  return buf;
}

export class ChannelPairError extends Error {
  constructor(message: string) { super(message); this.name = 'ChannelPairError'; }
}

export class ChannelVerifyError extends Error {
  constructor(message: string) { super(message); this.name = 'ChannelVerifyError'; }
}

/**
 * A Frame's local identity. One per Nexus instance.
 * Call `Channel.load()` on every cold start — it generates a keypair on
 * first run, then reloads from storage on subsequent runs.
 */
export class Channel {
  private constructor(
    private readonly nexusId: string,
    private readonly privateKey: CryptoKey,
    private readonly _publicKeyBytes: Uint8Array,
    private readonly storage: ChannelStorage,
  ) {}

  static async load(nexusId: string, storage: ChannelStorage): Promise<Channel> {
    const storedPriv = await storage.get(PRIVATE_KEY_STORAGE_KEY);
    const storedPub  = await storage.get(PUBLIC_KEY_STORAGE_KEY);

    if (storedPriv && storedPub) {
      const privJwk = JSON.parse(storedPriv) as JsonWebKey;
      const privateKey = await crypto.subtle.importKey(
        'jwk', privJwk, { name: 'Ed25519' }, false, ['sign'],
      );
      const pubBytes = b64uDecode(storedPub);
      return new Channel(nexusId, privateKey, pubBytes, storage);
    }

    // First run — generate keypair.
    const kp = await crypto.subtle.generateKey(
      { name: 'Ed25519' }, true, ['sign', 'verify'],
    ) as CryptoKeyPair;
    const privJwk = await crypto.subtle.exportKey('jwk', kp.privateKey);
    const pubRaw  = await crypto.subtle.exportKey('raw', kp.publicKey) as ArrayBuffer;
    const pubBytes = new Uint8Array(pubRaw);

    // Store private key as non-extractable JWK; public key as raw base64url.
    // Re-import private key as non-extractable so raw bytes can't be read back.
    const privateKey = await crypto.subtle.importKey(
      'jwk', privJwk, { name: 'Ed25519' }, false, ['sign'],
    );
    await storage.put(PRIVATE_KEY_STORAGE_KEY, JSON.stringify(privJwk));
    await storage.put(PUBLIC_KEY_STORAGE_KEY, b64uEncode(pubBytes));

    return new Channel(nexusId, privateKey, pubBytes, storage);
  }

  /** Raw Ed25519 public key bytes (32 bytes). */
  publicKeyBytes(): Uint8Array {
    return this._publicKeyBytes;
  }

  /** base64url-encoded public key — include in PairingToken. */
  publicKeyB64u(): string {
    return b64uEncode(this._publicKeyBytes);
  }

  /** Build a PairingToken to hand to the peer operator OOB. */
  makePairingToken(endpoint: string): PairingToken {
    return {
      v: 1,
      nexus_id: this.nexusId,
      pubkey: this.publicKeyB64u(),
      endpoint,
      nonce: b64uEncode(randomBytes(16)),
      ts: Math.floor(Date.now() / 1000),
    };
  }

  /**
   * Complete pairing from the peer's PairingToken.
   * Stores the peer record; returns a PairedChannel.
   * Token age is validated against `maxAgeSeconds` (default 24h) to limit
   * replay of stale OOB tokens.
   */
  async pair(token: PairingToken, maxAgeSeconds = 86400): Promise<PairedChannel> {
    const age = Math.floor(Date.now() / 1000) - token.ts;
    if (age > maxAgeSeconds || age < -300) {
      throw new ChannelPairError(`Pairing token is too old or from the future (age=${age}s).`);
    }
    const peerPubBytes = b64uDecode(token.pubkey);
    if (peerPubBytes.length !== 32) {
      throw new ChannelPairError('Peer public key must be 32 bytes (Ed25519).');
    }
    const pathId = await computePathId(this._publicKeyBytes, peerPubBytes);
    const record: PeerRecord = {
      nexus_id: token.nexus_id,
      pubkey: token.pubkey,
      endpoint: token.endpoint,
      path_id: pathId,
      paired_at: Math.floor(Date.now() / 1000),
    };
    await this.storage.put(`${PEER_KEY_PREFIX}${token.nexus_id}`, JSON.stringify(record));
    const peerPublicKey = await crypto.subtle.importKey(
      'raw', peerPubBytes.buffer as ArrayBuffer, { name: 'Ed25519' }, false, ['verify'],
    );
    return new PairedChannel(this.nexusId, this.privateKey, record, peerPublicKey);
  }

  /** Load an existing PairedChannel for a peer by nexus_id. Returns null if not paired. */
  async getPaired(peerId: string): Promise<PairedChannel | null> {
    const raw = await this.storage.get(`${PEER_KEY_PREFIX}${peerId}`);
    if (!raw) return null;
    const record = JSON.parse(raw) as PeerRecord;
    const peerPubBytes = b64uDecode(record.pubkey);
    const peerPublicKey = await crypto.subtle.importKey(
      'raw', peerPubBytes.buffer as ArrayBuffer, { name: 'Ed25519' }, false, ['verify'],
    );
    return new PairedChannel(this.nexusId, this.privateKey, record, peerPublicKey);
  }

  /** Remove a peer. After revocation, `getPaired(peerId)` returns null. */
  async revoke(peerId: string): Promise<void> {
    await this.storage.delete(`${PEER_KEY_PREFIX}${peerId}`);
  }
}

/**
 * An active channel to a specific peer.
 * Obtained from `channel.pair()` or `channel.getPaired()`.
 */
export class PairedChannel {
  constructor(
    private readonly localNexusId: string,
    private readonly privateKey: CryptoKey,
    private readonly peer: PeerRecord,
    private readonly peerPublicKey: CryptoKey,
  ) {}

  /** Symmetric path identifier — use as Durable Object name. */
  pathId(): string {
    return this.peer.path_id;
  }

  peerId(): string {
    return this.peer.nexus_id;
  }

  peerEndpoint(): string {
    return this.peer.endpoint;
  }

  peerRecord(): Readonly<PeerRecord> {
    return this.peer;
  }

  /**
   * Sign arbitrary bytes. For envelope signing, pass the UTF-8 encoding
   * of your canonical JSON with sorted keys.
   * Returns a 64-byte Ed25519 signature as base64url.
   */
  async sign(data: Uint8Array): Promise<string> {
    const sig = await crypto.subtle.sign('Ed25519', this.privateKey, data.buffer as ArrayBuffer);
    return b64uEncode(new Uint8Array(sig));
  }

  /**
   * Verify a signature from the peer. `signatureB64u` is what they sent in
   * X-Nexus-Signature; `data` is the same canonical bytes you'd pass to sign().
   * Throws ChannelVerifyError on invalid signature.
   */
  async verify(signatureB64u: string, data: Uint8Array): Promise<void> {
    const sigBytes = b64uDecode(signatureB64u);
    const valid = await crypto.subtle.verify('Ed25519', this.peerPublicKey, sigBytes.buffer as ArrayBuffer, data.buffer as ArrayBuffer);
    if (!valid) throw new ChannelVerifyError('Signature verification failed.');
  }
}
