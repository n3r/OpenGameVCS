import { identityFail } from './errors.mjs';

export class MemoryBootstrapStore {
  #state = null;

  read() { return this.#state === null ? null : structuredClone(this.#state); }

  create(state) {
    if (this.#state !== null) identityFail('STATE_CONFLICT', 'bootstrap state already exists');
    this.#state = structuredClone(state);
  }

  compareAndSwap(expectedGeneration, state) {
    if (this.#state === null || this.#state.generation !== expectedGeneration
        || state.generation !== expectedGeneration + 1) identityFail('STATE_CONFLICT', 'bootstrap state changed');
    this.#state = structuredClone(state);
  }
}

