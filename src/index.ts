export type { CasketAlgorithm, CasketKdf, CasketOptions } from './casket.js';
export {
  sealWithPassword,
  unsealWithPassword,
  sealWithKey,
  unsealWithKey,
  sealWithKeyAsync,
  unsealWithKeyAsync,
  generateKey,
} from './casket.js';
export type { CasketKeySource, AsyncCasketKeySource } from './keysource.js';
export { keySourceFromEnv, keySourceFromFile, keySourceFromBuffer } from './keysource.js';
export { CasketKeyRing } from './keyring.js';
export { CasketKeyPolicy } from './keypolicy.js';
export type { CasketKeyPolicyOptions } from './keypolicy.js';
export {
  CasketError,
  CasketDecryptionError,
  CasketStreamTruncatedError,
  CasketStreamCorruptedError,
  CasketKeyLimitExceededError,
  CasketConfigurationError,
  CasketKeyNotFoundError,
  CasketUnsupportedVersionError,
} from './errors.js';

export type { ChannelStorage, PairingToken, PeerRecord, InterchangeHalf } from './channel.js';
export { Channel, PairedChannel, ChannelPairError, ChannelVerifyError, ChannelDecryptError } from './channel.js';

// Internal exports for testing (fixed-nonce sealing)
export { sealPassword, unsealPassword, sealRawKey, unsealRawKey } from './internal/wire/blob.js';
export { encode as base64UrlEncode, decode as base64UrlDecode } from './internal/base64url.js';
