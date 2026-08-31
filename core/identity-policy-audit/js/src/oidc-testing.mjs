import { identityFail } from './errors.mjs';
import { RUNTIME_LIMITS, cloneBounded } from './validate.mjs';

function clone(value) {
  return cloneBounded(value, { maxBytes: 64 * 1024, maxDepth: 8, maxNodes: 1_000, maxStringBytes: 8_192 });
}

export class MemoryAuthenticationTransactionStore {
  #maximum;
  #records = new Map();
  #secrets = new Map();

  constructor({ maximum = RUNTIME_LIMITS.maxAuthenticationTransactions } = {}) {
    if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > RUNTIME_LIMITS.maxAuthenticationTransactions) {
      identityFail('INPUT_INVALID', 'authentication transaction bound is invalid');
    }
    this.#maximum = maximum;
  }

  create(record, secrets) {
    if (this.#records.has(record.id)) identityFail('STATE_CONFLICT', 'authentication transaction repeats');
    if (this.#records.size >= this.#maximum) identityFail('LIMIT_EXCEEDED', 'authentication transaction bound exceeded');
    this.#records.set(record.id, clone(record));
    this.#secrets.set(record.id, clone(secrets));
  }

  claim(id, expectedStateDigest, now) {
    const record = this.#records.get(id);
    if (!record || record.state !== 'pending' || !Number.isSafeInteger(now) || now >= record.expiresAt
        || (expectedStateDigest !== null && record.stateDigest !== expectedStateDigest)) {
      identityFail('AUTHENTICATION_DENIED');
    }
    record.state = 'claimed';
    const secrets = this.#secrets.get(id);
    if (!secrets) identityFail('POLICY_UNAVAILABLE', 'authentication transaction secret is unavailable');
    return { record: clone(record), secrets: clone(secrets) };
  }

  release(id, nextPollAt, secrets) {
    const record = this.#records.get(id);
    if (!record || record.state !== 'claimed' || !Number.isSafeInteger(nextPollAt)
        || nextPollAt < record.createdAt || nextPollAt >= record.expiresAt) identityFail('STATE_CONFLICT');
    record.nextPollAt = nextPollAt; record.state = 'pending'; this.#secrets.set(id, clone(secrets));
  }

  finish(id, state) {
    const record = this.#records.get(id);
    if (!record || record.state !== 'claimed' || !['complete', 'failed'].includes(state)) identityFail('STATE_CONFLICT');
    record.state = state;
    this.#secrets.delete(id);
  }

  inspect(id) { return this.#records.has(id) ? clone(this.#records.get(id)) : null; }
}
