import { canonicalDigest, deepFreeze } from './canonical.mjs';
import { harnessFail } from './errors.mjs';
import { HARNESS_LIMITS, boundedInteger, checkedAdd } from './limits.mjs';

const STATES = Object.freeze({
  cold: { localBytes: 0, regionalBytes: 0 },
  'warm-local-cache': { localBytes: 65_536, regionalBytes: 0 },
  'warm-regional-cache': { localBytes: 0, regionalBytes: 65_536 },
  'mixed-cache': { localBytes: 32_768, regionalBytes: 65_536 },
});

export class DeterministicCacheController {
  #state = 'cold';
  #localBytes = 0;
  #regionalBytes = 0;
  #reads = 0;
  #originBytes = 0;
  #localHits = 0;
  #regionalHits = 0;
  #maximumBytes;
  constructor(options = {}) {
    this.#maximumBytes = boundedInteger(options.maxBytes, HARNESS_LIMITS.maxWorkingMemoryBytes, HARNESS_LIMITS.maxWorkingMemoryBytes, 'cache maxBytes');
  }
  prepare(state) {
    const target = STATES[state];
    if (!target) harnessFail('HARNESS_CACHE_STATE_INVALID', 'cache state is not registered');
    if (target.localBytes + target.regionalBytes > this.#maximumBytes) harnessFail('HARNESS_LIMIT_EXCEEDED', 'cache fixture exceeds its configured byte bound');
    this.#state = state;
    this.#localBytes = target.localBytes;
    this.#regionalBytes = target.regionalBytes;
    this.#reads = 0; this.#originBytes = 0; this.#localHits = 0; this.#regionalHits = 0;
    return this.inspect();
  }
  read(bytes) {
    if (!Number.isSafeInteger(bytes) || bytes < 0) harnessFail('HARNESS_INPUT_INVALID', 'cache read size is invalid');
    const reads = checkedAdd(this.#reads, 1, 'cache reads');
    let localBytes = this.#localBytes; let originBytes = this.#originBytes; let localHits = this.#localHits; let regionalHits = this.#regionalHits;
    if (this.#state === 'warm-local-cache' || this.#state === 'mixed-cache' && reads % 2 === 1) localHits = checkedAdd(localHits, 1, 'local cache hits');
    else if (this.#state === 'warm-regional-cache' || this.#state === 'mixed-cache') {
      regionalHits = checkedAdd(regionalHits, 1, 'regional cache hits');
      const next = checkedAdd(localBytes, bytes, 'local cache bytes');
      if (checkedAdd(next, this.#regionalBytes, 'aggregate cache bytes') > this.#maximumBytes) harnessFail('HARNESS_LIMIT_EXCEEDED', 'cache read exceeds its configured byte bound');
      localBytes = next;
    } else {
      originBytes = checkedAdd(originBytes, bytes, 'origin cache bytes');
      const next = checkedAdd(localBytes, bytes, 'local cache bytes');
      if (checkedAdd(next, this.#regionalBytes, 'aggregate cache bytes') > this.#maximumBytes) harnessFail('HARNESS_LIMIT_EXCEEDED', 'cache read exceeds its configured byte bound');
      localBytes = next;
    }
    this.#reads = reads; this.#localBytes = localBytes; this.#originBytes = originBytes; this.#localHits = localHits; this.#regionalHits = regionalHits;
    return this.inspect();
  }
  inspect() {
    const body = { state: this.#state, localBytes: this.#localBytes, regionalBytes: this.#regionalBytes, reads: this.#reads, localHits: this.#localHits, regionalHits: this.#regionalHits, originBytes: this.#originBytes };
    return deepFreeze({ ...body, stateDigest: canonicalDigest(body, 'ogvcs.benchmark/cache-inspection/v1') });
  }
}

export function registeredCacheStates() { return Object.keys(STATES); }
