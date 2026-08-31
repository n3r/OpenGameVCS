import { identityFail } from './errors.mjs';

export class MemoryTrustedAuditCheckpointStore {
  #checkpoints = new Map();

  retain(checkpoint) {
    if (!checkpoint || typeof checkpoint !== 'object' || typeof checkpoint.tenant !== 'string') identityFail('INPUT_INVALID');
    this.#checkpoints.set(checkpoint.tenant, structuredClone(checkpoint));
  }

  get(tenant) { return this.#checkpoints.has(tenant) ? structuredClone(this.#checkpoints.get(tenant)) : null; }
}

