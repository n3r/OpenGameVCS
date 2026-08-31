import { canonicalBytes, sha256 } from '@opengamevcs/authorization-contract';

import { identityFail } from './errors.mjs';

const DOMAIN = Buffer.from('OGVCS-IDENTITY-DECISION-COMMITMENT-V1\0', 'ascii');

export class MemoryAuthorizationTransactionParticipant {
  #chains = new Map();
  #nextTransaction = 1;
  #policies = new Map();
  #poisoned = new WeakSet();
  #transactionIds = new WeakMap();
  #transactions = new WeakSet();

  initializePolicy(tenant, policy) { this.#policies.set(tenant, structuredClone(policy)); }
  open() {
    const transaction = {};
    this.#transactions.add(transaction);
    this.#transactionIds.set(transaction, `memory.tx.${this.#nextTransaction++}`);
    return transaction;
  }

  transactionId(transaction) {
    this.#active(transaction);
    return this.#transactionIds.get(transaction);
  }

  readPolicy(transaction, tenant) {
    this.#active(transaction);
    return this.#policies.has(tenant) ? structuredClone(this.#policies.get(tenant)) : null;
  }

  appendDecisionCommitment(transaction, core) {
    this.#active(transaction);
    const chain = this.#chains.get(core.tenant) ?? [];
    const value = {
      ...structuredClone(core), commitmentId: `decision.${core.transactionId}.${chain.length + 1}`,
      sequence: chain.length + 1, previousHash: chain.at(-1)?.recordHash ?? null,
    };
    value.recordHash = sha256(Buffer.concat([DOMAIN, canonicalBytes(value)]));
    chain.push(structuredClone(value)); this.#chains.set(core.tenant, chain);
    return value;
  }

  poison(transaction) {
    if (!this.#transactions.has(transaction)) identityFail('STATE_CONFLICT', 'authorization transaction is not active');
    this.#poisoned.add(transaction);
  }

  close(transaction) { this.#transactions.delete(transaction); this.#poisoned.delete(transaction); this.#transactionIds.delete(transaction); }
  commitments(tenant) { return structuredClone(this.#chains.get(tenant) ?? []); }

  #active(transaction) {
    if (!this.#transactions.has(transaction) || this.#poisoned.has(transaction)) {
      identityFail('STATE_CONFLICT', 'authorization transaction is not active');
    }
  }
}
