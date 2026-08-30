import { cloneBounded, deepFreeze } from './validate.mjs';
import { identityFail } from './errors.mjs';

const FLOWS = Object.freeze(['authorization-code-pkce', 'device-code']);

export function assertIdentityProviderAdapter(adapter) {
  if (!adapter || typeof adapter !== 'object' || typeof adapter.id !== 'string'
      || !Array.isArray(adapter.flows) || adapter.flows.length === 0
      || adapter.flows.some((flow) => !FLOWS.includes(flow))
      || typeof adapter.begin !== 'function' || typeof adapter.complete !== 'function') {
    identityFail('INPUT_INVALID', 'identity-provider adapter is invalid');
  }
  return adapter;
}

export class IdentityProviderBroker {
  #adapters = new Map();

  constructor(adapters = []) {
    for (const adapter of adapters) {
      assertIdentityProviderAdapter(adapter);
      if (this.#adapters.has(adapter.id)) identityFail('INPUT_INVALID', 'identity-provider adapter ID repeats');
      this.#adapters.set(adapter.id, adapter);
    }
  }

  async begin(adapterId, flow, input, options = {}) {
    const adapter = this.#adapter(adapterId, flow);
    try { return deepFreeze(cloneBounded(await adapter.begin(flow, cloneBounded(input), { signal: options.signal }), { maxBytes: 64 * 1024 })); }
    catch (error) { identityFail('AUTHENTICATION_DENIED', 'identity-provider begin failed', { cause: error }); }
  }

  async complete(adapterId, flow, input, options = {}) {
    const adapter = this.#adapter(adapterId, flow);
    try { return deepFreeze(cloneBounded(await adapter.complete(flow, cloneBounded(input), { signal: options.signal }), { maxBytes: 64 * 1024 })); }
    catch (error) { identityFail('AUTHENTICATION_DENIED', 'identity-provider completion failed', { cause: error }); }
  }

  #adapter(id, flow) {
    const adapter = this.#adapters.get(id);
    if (!adapter || !adapter.flows.includes(flow)) identityFail('AUTHENTICATION_DENIED');
    return adapter;
  }
}
