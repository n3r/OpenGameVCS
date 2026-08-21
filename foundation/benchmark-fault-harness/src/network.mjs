import { cloneData, deepFreeze } from './canonical.mjs';
import { harnessFail } from './errors.mjs';
import { HARNESS_LIMITS, checkedAdd } from './limits.mjs';
import { setTimeout as wait } from 'node:timers/promises';

function resetAfterFailedApply(adapter) {
  try {
    const reset = adapter.reset();
    if (reset && typeof reset.then === 'function') {
      void reset.catch(() => {});
      harnessFail('HARNESS_IO', 'privileged network adapter cleanup must complete synchronously');
    }
  } catch (error) {
    if (error?.code?.startsWith?.('HARNESS_')) throw error;
    harnessFail('HARNESS_IO', 'privileged network adapter could not reset after failed apply', { cause: error });
  }
}

export class NetworkController {
  #profile;
  #sequence = 0;
  #sent = 0;
  #received = 0;
  #effects = [];
  #simulateDelay;
  #signal;
  constructor(profile, options = {}) {
    try { profile = cloneData(profile); }
    catch (error) { harnessFail('HARNESS_INPUT_INVALID', 'network profile must be inert bounded canonical data', { cause: error }); }
    if (!profile || typeof profile.id !== 'string' || !['simulated', 'privileged'].includes(profile.mode) || !Number.isSafeInteger(profile.rttMs) || profile.rttMs < 0 || profile.rttMs > 200 || !Number.isSafeInteger(profile.bandwidthBytesPerSecond) || profile.bandwidthBytesPerSecond < 0 || !Number.isSafeInteger(profile.lossPartsPerMillion) || profile.lossPartsPerMillion < 0 || profile.lossPartsPerMillion > 1_000_000 || !Number.isSafeInteger(profile.interruptionEvery) || profile.interruptionEvery < 0 || !Number.isSafeInteger(profile.duplicateEvery) || profile.duplicateEvery < 0 || !Number.isSafeInteger(profile.reorderWindow) || profile.reorderWindow < 0 || profile.reorderWindow > 1024) harnessFail('HARNESS_INPUT_INVALID', 'network profile is invalid');
    if (options.signal !== undefined && !(options.signal instanceof AbortSignal)) harnessFail('HARNESS_INPUT_INVALID', 'network signal must be an AbortSignal');
    if (profile.mode === 'privileged') {
      if (options.allowPrivileged !== true || !options.adapter || options.adapter.isolated !== true || typeof options.adapter.apply !== 'function' || typeof options.adapter.reset !== 'function') harnessFail('HARNESS_PRIVILEGE_REQUIRED', 'privileged network profile requires an explicit isolated adapter');
      try {
        const applied = options.adapter.apply(profile);
        if (applied && typeof applied.then === 'function') harnessFail('HARNESS_INPUT_INVALID', 'privileged network adapter apply must complete synchronously');
      } catch (error) {
        resetAfterFailedApply(options.adapter);
        if (error?.code?.startsWith?.('HARNESS_')) throw error;
        harnessFail('HARNESS_IO', 'privileged network adapter could not apply its isolated profile', { cause: error });
      }
      this.adapter = options.adapter;
    }
    this.#profile = deepFreeze({ ...profile });
    this.#simulateDelay = options.simulateDelay !== false;
    this.#signal = options.signal;
  }
  planTransfer(bytes, direction = 'send') {
    if (!Number.isSafeInteger(bytes) || bytes < 0 || !['send', 'receive'].includes(direction)) harnessFail('HARNESS_INPUT_INVALID', 'network transfer is invalid');
    const sequence = checkedAdd(this.#sequence, 1, 'network transfer sequence');
    if (sequence > HARNESS_LIMITS.maxTraceEvents) harnessFail('HARNESS_LIMIT_EXCEEDED', 'network transfer count exceeds its configured bound');
    const effects = [];
    if (this.#profile.interruptionEvery > 0 && sequence % this.#profile.interruptionEvery === 0) effects.push('interrupt');
    if (this.#profile.duplicateEvery > 0 && sequence % this.#profile.duplicateEvery === 0) effects.push('duplicate');
    if (this.#profile.reorderWindow > 0 && sequence % this.#profile.reorderWindow === 0) effects.push('reorder');
    if (this.#profile.lossPartsPerMillion > 0 && (sequence * 104_729) % 1_000_000 < this.#profile.lossPartsPerMillion) effects.push('loss');
    if (this.#effects.length + effects.length > HARNESS_LIMITS.maxTraceEvents) harnessFail('HARNESS_LIMIT_EXCEEDED', 'network effect trace exceeds its configured bound');
    const retries = Number(effects.includes('interrupt')) + Number(effects.includes('loss'));
    const copies = 1 + retries + Number(effects.includes('duplicate'));
    const wireBytes = bytes === 0 ? 0 : checkedAdd(bytes, bytes * (copies - 1), 'network wire bytes');
    const sent = direction === 'send' ? checkedAdd(this.#sent, wireBytes, 'network sent bytes') : this.#sent;
    const received = direction === 'receive' ? checkedAdd(this.#received, wireBytes, 'network received bytes') : this.#received;
    const serialization = this.#profile.bandwidthBytesPerSecond === 0 ? 0 : Math.ceil(wireBytes * 1_000_000 / this.#profile.bandwidthBytesPerSecond);
    const delayMicroseconds = checkedAdd(this.#profile.rttMs * 1000 * (1 + retries), serialization, 'network delay');
    this.#sequence = sequence; this.#sent = sent; this.#received = received;
    this.#effects.push(...effects.map((effect) => ({ sequence, effect })));
    return deepFreeze({ delayMicroseconds, effects, retries, wireBytes });
  }
  async transfer(bytes, direction = 'send', signal = this.#signal) {
    if (signal !== undefined && !(signal instanceof AbortSignal)) harnessFail('HARNESS_INPUT_INVALID', 'network transfer signal must be an AbortSignal');
    if (signal?.aborted) harnessFail('HARNESS_CANCELLED', 'network transfer was cancelled before accounting');
    const checkpoint = { sequence: this.#sequence, sent: this.#sent, received: this.#received, effects: this.#effects.length };
    const result = this.planTransfer(bytes, direction);
    try {
      if (this.#simulateDelay && result.delayMicroseconds > 0) await wait(Math.ceil(result.delayMicroseconds / 1000), undefined, { signal });
      if (signal?.aborted) harnessFail('HARNESS_CANCELLED', 'network transfer was cancelled');
      return result;
    } catch (error) {
      this.#sequence = checkpoint.sequence; this.#sent = checkpoint.sent; this.#received = checkpoint.received; this.#effects.length = checkpoint.effects;
      if (error?.name === 'AbortError') harnessFail('HARNESS_CANCELLED', 'network transfer was cancelled');
      throw error;
    }
  }
  inspect() { return deepFreeze({ profile: this.#profile, sentBytes: this.#sent, receivedBytes: this.#received, effects: this.#effects.map((effect) => ({ ...effect })) }); }
  reset() {
    if (!this.adapter) return;
    try {
      const reset = this.adapter.reset();
      if (reset && typeof reset.then === 'function') harnessFail('HARNESS_INPUT_INVALID', 'privileged network adapter reset must complete synchronously');
    } catch (error) {
      if (error?.code?.startsWith?.('HARNESS_')) throw error;
      harnessFail('HARNESS_IO', 'privileged network adapter could not reset its isolated profile', { cause: error });
    }
  }
}
