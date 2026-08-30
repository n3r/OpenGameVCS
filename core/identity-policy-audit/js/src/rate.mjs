import { identityFail } from './errors.mjs';
import { RUNTIME_LIMITS } from './validate.mjs';

export class FixedWindowRateLimiter {
  #buckets = new Map();
  #clock;
  #limit;
  #maximum;
  #windowSeconds;

  constructor({ limit, windowSeconds, clock = () => Math.floor(Date.now() / 1000), maxBuckets = RUNTIME_LIMITS.maxRateBuckets }) {
    if (!Number.isSafeInteger(limit) || limit < 1 || !Number.isSafeInteger(windowSeconds) || windowSeconds < 1
        || !Number.isSafeInteger(maxBuckets) || maxBuckets < 1 || maxBuckets > RUNTIME_LIMITS.maxRateBuckets) identityFail('INPUT_INVALID', 'rate limit configuration is invalid');
    this.#limit = limit; this.#windowSeconds = windowSeconds; this.#clock = clock; this.#maximum = maxBuckets;
  }

  consume(key, requestClass) {
    if (typeof key !== 'string' || key.length < 1 || key.length > 256 || typeof requestClass !== 'string' || requestClass.length < 1 || requestClass.length > 64) identityFail('INPUT_INVALID', 'rate key is invalid');
    let now;
    try { now = this.#clock(); }
    catch { return Object.freeze({ allowed: false, retryAfterSeconds: this.#windowSeconds }); }
    if (!Number.isSafeInteger(now) || now < 0) return Object.freeze({ allowed: false, retryAfterSeconds: this.#windowSeconds });
    const bucketKey = `${requestClass}\0${key}`;
    const window = Math.floor(now / this.#windowSeconds);
    let bucket = this.#buckets.get(bucketKey);
    if (!bucket || bucket.window !== window) {
      if (!bucket && this.#buckets.size >= this.#maximum) {
        for (const [candidate, value] of this.#buckets) if (value.window !== window) this.#buckets.delete(candidate);
        if (this.#buckets.size >= this.#maximum) return Object.freeze({ allowed: false, retryAfterSeconds: this.#windowSeconds });
      }
      bucket = { window, count: 0 };
      this.#buckets.set(bucketKey, bucket);
    }
    bucket.count += 1;
    return Object.freeze({ allowed: bucket.count <= this.#limit, retryAfterSeconds: this.#windowSeconds - (now % this.#windowSeconds) });
  }
}
