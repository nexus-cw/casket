export class CasketError extends Error {
  constructor(message: string) { super(message); this.name = 'CasketError'; }
}

export class CasketDecryptionError extends CasketError {
  constructor() { super('Decryption failed.'); this.name = 'CasketDecryptionError'; }
}

export class CasketStreamTruncatedError extends CasketError {
  constructor() { super('Stream was truncated before the final chunk was reached.'); this.name = 'CasketStreamTruncatedError'; }
}

export class CasketStreamCorruptedError extends CasketError {
  constructor(detail: string) { super(`Stream is structurally invalid: ${detail}`); this.name = 'CasketStreamCorruptedError'; }
}

export class CasketKeyLimitExceededError extends CasketError {
  sealCount: bigint;
  hardLimit: bigint;
  constructor(sealCount: bigint, hardLimit: bigint) {
    super(`Key seal limit exceeded (${sealCount}/${hardLimit}). Rotate the key.`);
    this.name = 'CasketKeyLimitExceededError';
    this.sealCount = sealCount;
    this.hardLimit = hardLimit;
  }
}

export class CasketConfigurationError extends CasketError {
  constructor(detail: string) { super(detail); this.name = 'CasketConfigurationError'; }
}

export class CasketKeyNotFoundError extends CasketError {
  keyId: number;
  constructor(keyId: number) {
    super(`No key registered for key ID 0x${keyId.toString(16).padStart(4, '0').toUpperCase()}.`);
    this.name = 'CasketKeyNotFoundError';
    this.keyId = keyId;
  }
}

export class CasketUnsupportedVersionError extends CasketError {
  version: number;
  constructor(version: number) {
    super(`Unsupported token version: 0x${version.toString(16).padStart(2, '0').toUpperCase()}.`);
    this.name = 'CasketUnsupportedVersionError';
    this.version = version;
  }
}
