import { AuditLedger, MemoryAuditStore } from './audit.mjs';
import { identityFail } from './errors.mjs';

export class MemoryPolicyAuthorityStore {
  #auditStore = new MemoryAuditStore();
  #policies = new Map();

  initialize(tenant, policy) {
    if (this.#policies.has(tenant)) identityFail('STATE_CONFLICT', 'policy already exists');
    this.#policies.set(tenant, structuredClone(policy));
  }

  read(tenant) { return this.#policies.has(tenant) ? structuredClone(this.#policies.get(tenant)) : null; }

  compareAndSwapWithAudit({ tenant, expectedGeneration, nextPolicy, event }) {
    const current = this.#policies.get(tenant);
    if (!current || current.generation !== expectedGeneration) identityFail('STATE_CONFLICT', 'policy generation changed');
    const ledger = new AuditLedger({ store: this.#auditStore });
    const record = ledger.append(event);
    this.#policies.set(tenant, structuredClone(nextPolicy));
    return { policyGeneration: nextPolicy.generation, auditRecordHash: record.recordHash };
  }

  auditLedger() { return new AuditLedger({ store: this.#auditStore }); }
}

