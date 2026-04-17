import { CasketKeyLimitExceededError } from './errors.js';

export interface CasketKeyPolicyOptions {
  hardLimit?: bigint;
  warnThreshold?: bigint;
  onApproachingLimit?: (args: { sealCount: bigint; hardLimit: bigint }) => void;
}

export class CasketKeyPolicy {
  private _sealCount = 0n;
  readonly hardLimit: bigint;
  readonly warnThreshold: bigint | undefined;
  readonly onApproachingLimit: ((args: { sealCount: bigint; hardLimit: bigint }) => void) | undefined;

  constructor(options: CasketKeyPolicyOptions = {}) {
    this.hardLimit = options.hardLimit ?? 4_294_967_295n;
    this.warnThreshold = options.warnThreshold;
    this.onApproachingLimit = options.onApproachingLimit;
  }

  get sealCount(): bigint { return this._sealCount; }

  reset(): void { this._sealCount = 0n; }

  recordSeal(): void {
    this._sealCount += 1n;
    if (this._sealCount > this.hardLimit)
      throw new CasketKeyLimitExceededError(this._sealCount, this.hardLimit);
    if (this.warnThreshold !== undefined && this._sealCount === this.warnThreshold)
      this.onApproachingLimit?.({ sealCount: this._sealCount, hardLimit: this.hardLimit });
  }
}
