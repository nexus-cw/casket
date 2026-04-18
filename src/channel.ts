/**
 * Ed25519 + X25519 channel identity for Frame-to-Frame relay.
 *
 * Each Frame holds two keypairs:
 *   - Ed25519 (signing/verification) — non-repudiation on outer envelope
 *   - X25519 (ECDH) — derives a shared symmetric key for body encryption
 *
 * Pairing exchanges both public keys OOB (single PairingToken blob).
 * PairedChannel holds the derived shared key; bodies are AEAD-encrypted
 * so the interchange sees only ciphertext + routing metadata.
 *
 * Storage is injected ({get, put, delete}) — drop in Workers KV or any
 * async k/v. Private key bytes never leave the runtime once imported.
 */

export interface ChannelStorage {
  get(key: string): Promise<string | null>;
  put(key: string, value: string): Promise<void>;
  delete(key: string): Promise<void>;
}

export interface PairingToken {
  v: 1;
  nexus_id: string;
  pubkey: string;     // base64url Ed25519 public key (32 bytes) — for sign/verify
  dh_pubkey: string;  // base64url X25519 public key (32 bytes) — for ECDH
  endpoint: string;   // https URL of this frame's relay Worker
  nonce: string;      // base64url 16 random bytes — OOB token replay guard
  ts: number;         // unix seconds
}

export interface PeerRecord {
  nexus_id: string;
  pubkey: string;     // base64url Ed25519
  dh_pubkey: string;  // base64url X25519
  endpoint: string;
  path_id: string;    // nxc_<base64url(sha256(sort(ed25519_pubA, ed25519_pubB)))>
  paired_at: number;  // unix seconds
}

const PRIVATE_KEY_STORAGE_KEY    = 'casket:channel:private_key';
const PUBLIC_KEY_STORAGE_KEY     = 'casket:channel:public_key';
const DH_PRIVATE_KEY_STORAGE_KEY = 'casket:channel:dh_private_key';
const DH_PUBLIC_KEY_STORAGE_KEY  = 'casket:channel:dh_public_key';
const PEER_KEY_PREFIX            = 'casket:peers:';

const NONCE_SIZE = 12;
const TAG_SIZE   = 16;

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
  const [first, second] = compareBytes(pubA, pubB) <= 0
    ? [pubA, pubB] : [pubB, pubA];
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

async function deriveSharedKey(
  localDhPrivate: CryptoKey,
  peerDhPubBytes: Uint8Array,
): Promise<CryptoKey> {
  const peerDhPublic = await crypto.subtle.importKey(
    'raw', Buffer.from(peerDhPubBytes),
    { name: 'ECDH', namedCurve: 'P-256' }, false, [],
  );
  const rawSecret = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: peerDhPublic }, localDhPrivate, 256,
  ) as ArrayBuffer;
  // HKDF over the raw secret to produce a 256-bit AES-GCM key.
  const hkdfKey = await crypto.subtle.importKey('raw', rawSecret, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode('nexus-casket-channel-v1') },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

export class ChannelPairError extends Error {
  constructor(message: string) { super(message); this.name = 'ChannelPairError'; }
}

export class ChannelVerifyError extends Error {
  constructor(message: string) { super(message); this.name = 'ChannelVerifyError'; }
}

export class ChannelDecryptError extends Error {
  constructor(message: string) { super(message); this.name = 'ChannelDecryptError'; }
}

/**
 * A Frame's local identity. One per Nexus instance.
 * Call `Channel.load()` on every cold start.
 */
export class Channel {
  private constructor(
    private readonly nexusId: string,
    private readonly sigPrivateKey: CryptoKey,
    private readonly _sigPublicKeyBytes: Uint8Array,
    private readonly dhPrivateKey: CryptoKey,
    private readonly _dhPublicKeyBytes: Uint8Array,
    private readonly storage: ChannelStorage,
  ) {}

  static async load(nexusId: string, storage: ChannelStorage): Promise<Channel> {
    const storedSigPriv = await storage.get(PRIVATE_KEY_STORAGE_KEY);
    const storedSigPub  = await storage.get(PUBLIC_KEY_STORAGE_KEY);
    const storedDhPriv  = await storage.get(DH_PRIVATE_KEY_STORAGE_KEY);
    const storedDhPub   = await storage.get(DH_PUBLIC_KEY_STORAGE_KEY);

    if (storedSigPriv && storedSigPub && storedDhPriv && storedDhPub) {
      const sigPrivateKey = await crypto.subtle.importKey(
        'jwk', JSON.parse(storedSigPriv) as JsonWebKey,
        { name: 'Ed25519' }, false, ['sign'],
      );
      const dhPrivateKey = await crypto.subtle.importKey(
        'jwk', JSON.parse(storedDhPriv) as JsonWebKey,
        { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits'],
      );
      return new Channel(
        nexusId,
        sigPrivateKey, b64uDecode(storedSigPub),
        dhPrivateKey,  b64uDecode(storedDhPub),
        storage,
      );
    }

    // First run — generate both keypairs.
    const sigKp = await crypto.subtle.generateKey(
      { name: 'Ed25519' }, true, ['sign', 'verify'],
    ) as CryptoKeyPair;
    const dhKp = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'],
    ) as CryptoKeyPair;

    const sigPrivJwk = await crypto.subtle.exportKey('jwk', sigKp.privateKey);
    const sigPubRaw  = new Uint8Array(await crypto.subtle.exportKey('raw', sigKp.publicKey) as ArrayBuffer);
    const dhPrivJwk  = await crypto.subtle.exportKey('jwk', dhKp.privateKey);
    const dhPubRaw   = new Uint8Array(await crypto.subtle.exportKey('raw', dhKp.publicKey) as ArrayBuffer);

    const sigPrivateKey = await crypto.subtle.importKey(
      'jwk', sigPrivJwk, { name: 'Ed25519' }, false, ['sign'],
    );
    const dhPrivateKey = await crypto.subtle.importKey(
      'jwk', dhPrivJwk, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits'],
    );

    await storage.put(PRIVATE_KEY_STORAGE_KEY,    JSON.stringify(sigPrivJwk));
    await storage.put(PUBLIC_KEY_STORAGE_KEY,     b64uEncode(sigPubRaw));
    await storage.put(DH_PRIVATE_KEY_STORAGE_KEY, JSON.stringify(dhPrivJwk));
    await storage.put(DH_PUBLIC_KEY_STORAGE_KEY,  b64uEncode(dhPubRaw));

    return new Channel(nexusId, sigPrivateKey, sigPubRaw, dhPrivateKey, dhPubRaw, storage);
  }

  publicKeyBytes(): Uint8Array { return this._sigPublicKeyBytes; }
  publicKeyB64u(): string      { return b64uEncode(this._sigPublicKeyBytes); }
  dhPublicKeyBytes(): Uint8Array { return this._dhPublicKeyBytes; }
  dhPublicKeyB64u(): string    { return b64uEncode(this._dhPublicKeyBytes); }

  /** Build a PairingToken to exchange OOB with the peer operator. */
  makePairingToken(endpoint: string): PairingToken {
    return {
      v: 1,
      nexus_id: this.nexusId,
      pubkey:    this.publicKeyB64u(),
      dh_pubkey: this.dhPublicKeyB64u(),
      endpoint,
      nonce: b64uEncode(randomBytes(16)),
      ts: Math.floor(Date.now() / 1000),
    };
  }

  /**
   * Complete pairing from the peer's PairingToken.
   * Derives the shared AEAD key via ECDH and stores the peer record.
   */
  async pair(token: PairingToken, maxAgeSeconds = 86400): Promise<PairedChannel> {
    const age = Math.floor(Date.now() / 1000) - token.ts;
    if (age > maxAgeSeconds || age < -300) {
      throw new ChannelPairError(`Pairing token is too old or from the future (age=${age}s).`);
    }

    const peerSigPubBytes = b64uDecode(token.pubkey);
    if (peerSigPubBytes.length !== 32) {
      throw new ChannelPairError('Peer Ed25519 public key must be 32 bytes.');
    }

    const peerDhPubBytes = b64uDecode(token.dh_pubkey);
    // P-256 uncompressed public key = 65 bytes (0x04 + 32 + 32)
    if (peerDhPubBytes.length !== 65) {
      throw new ChannelPairError('Peer X25519 (P-256) public key must be 65 bytes.');
    }

    const pathId = await computePathId(this._sigPublicKeyBytes, peerSigPubBytes);
    const sharedKey = await deriveSharedKey(this.dhPrivateKey, peerDhPubBytes);

    const record: PeerRecord = {
      nexus_id:  token.nexus_id,
      pubkey:    token.pubkey,
      dh_pubkey: token.dh_pubkey,
      endpoint:  token.endpoint,
      path_id:   pathId,
      paired_at: Math.floor(Date.now() / 1000),
    };
    await this.storage.put(`${PEER_KEY_PREFIX}${token.nexus_id}`, JSON.stringify(record));

    const peerSigPublicKey = await crypto.subtle.importKey(
      'raw', peerSigPubBytes.buffer as ArrayBuffer, { name: 'Ed25519' }, false, ['verify'],
    );
    return new PairedChannel(this.nexusId, this.sigPrivateKey, record, peerSigPublicKey, sharedKey);
  }

  /** Reload an existing PairedChannel from storage. Returns null if not paired. */
  async getPaired(peerId: string): Promise<PairedChannel | null> {
    const raw = await this.storage.get(`${PEER_KEY_PREFIX}${peerId}`);
    if (!raw) return null;
    const record = JSON.parse(raw) as PeerRecord;

    const peerSigPubBytes = b64uDecode(record.pubkey);
    const peerDhPubBytes  = b64uDecode(record.dh_pubkey);

    const peerSigPublicKey = await crypto.subtle.importKey(
      'raw', peerSigPubBytes.buffer as ArrayBuffer, { name: 'Ed25519' }, false, ['verify'],
    );
    const sharedKey = await deriveSharedKey(this.dhPrivateKey, peerDhPubBytes);

    return new PairedChannel(this.nexusId, this.sigPrivateKey, record, peerSigPublicKey, sharedKey);
  }

  /** Remove a peer. Fresh pair() after revocation produces a new pathId. */
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
    private readonly sigPrivateKey: CryptoKey,
    private readonly peer: PeerRecord,
    private readonly peerSigPublicKey: CryptoKey,
    private readonly sharedKey: CryptoKey,
  ) {}

  /** Symmetric path identifier — use as interchange mailbox address / DO name. */
  pathId(): string    { return this.peer.path_id; }
  peerId(): string    { return this.peer.nexus_id; }
  peerEndpoint(): string { return this.peer.endpoint; }
  peerRecord(): Readonly<PeerRecord> { return this.peer; }

  /**
   * Sign arbitrary bytes for the outer envelope.
   * Pass UTF-8(JSON.stringify(canonicalEnvelope, sortedKeys)).
   * Returns base64url Ed25519 signature (64 bytes).
   */
  async sign(data: Uint8Array): Promise<string> {
    const sig = await crypto.subtle.sign(
      'Ed25519', this.sigPrivateKey, data.buffer as ArrayBuffer,
    );
    return b64uEncode(new Uint8Array(sig));
  }

  /**
   * Verify a signature from the peer.
   * Throws ChannelVerifyError on bad signature.
   */
  async verify(signatureB64u: string, data: Uint8Array): Promise<void> {
    const sigBytes = b64uDecode(signatureB64u);
    const valid = await crypto.subtle.verify(
      'Ed25519', this.peerSigPublicKey,
      sigBytes.buffer as ArrayBuffer,
      data.buffer as ArrayBuffer,
    );
    if (!valid) throw new ChannelVerifyError('Signature verification failed.');
  }

  /**
   * Encrypt the message body (inner layer).
   * Returns `nonce (12 bytes) || tag (16 bytes) || ciphertext` as base64url.
   * `aad` is optional additional authenticated data (e.g. outer envelope bytes).
   */
  async encryptBody(plaintext: Uint8Array, aad?: Uint8Array): Promise<string> {
    const nonce = randomBytes(NONCE_SIZE);
    const ciphertextWithTag = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: Buffer.from(nonce), additionalData: aad ? Buffer.from(aad) : undefined },
      this.sharedKey,
      Buffer.from(plaintext),
    );
    const result = new Uint8Array(NONCE_SIZE + ciphertextWithTag.byteLength);
    result.set(nonce, 0);
    result.set(new Uint8Array(ciphertextWithTag), NONCE_SIZE);
    return b64uEncode(result);
  }

  /**
   * Decrypt a message body produced by `encryptBody`.
   * Throws ChannelDecryptError if authentication fails.
   */
  async decryptBody(ciphertextB64u: string, aad?: Uint8Array): Promise<Uint8Array> {
    const blob = b64uDecode(ciphertextB64u);
    if (blob.length < NONCE_SIZE + TAG_SIZE) {
      throw new ChannelDecryptError('Ciphertext too short.');
    }
    const nonce      = blob.slice(0, NONCE_SIZE);
    const ciphertext = blob.slice(NONCE_SIZE);
    try {
      const plaintext = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: Buffer.from(nonce), additionalData: aad ? Buffer.from(aad) : undefined },
        this.sharedKey,
        Buffer.from(ciphertext),
      );
      return new Uint8Array(plaintext);
    } catch {
      throw new ChannelDecryptError('Body decryption failed — wrong key or tampered ciphertext.');
    }
  }
}
