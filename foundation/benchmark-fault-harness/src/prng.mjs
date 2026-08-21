import { createHash } from 'node:crypto';
import { types as utilTypes } from 'node:util';

import { harnessFail } from './errors.mjs';

function seedBytes(seed) {
  if (typeof seed !== 'string' || seed.length < 1 || seed.length > 1024 || seed.includes('\0') || seed.normalize('NFC') !== seed || /[\uD800-\uDFFF]/u.test(seed)) harnessFail('HARNESS_INPUT_INVALID', 'fault seed must be bounded scalar NFC text');
  return createHash('sha256').update('ogvcs.benchmark/prng/v1\0').update(seed, 'utf8').digest();
}

function inertArray(values) {
  try {
    if (!Array.isArray(values) || utilTypes.isProxy(values) || Object.getPrototypeOf(values) !== Array.prototype || values.length > 1_048_576) harnessFail('HARNESS_INPUT_INVALID', 'PRNG shuffle input must be a bounded inert array');
    const keys = Reflect.ownKeys(values); const descriptors = Object.getOwnPropertyDescriptors(values);
    if (keys.some((key) => typeof key !== 'string') || keys.length !== values.length + 1 || !keys.includes('length')) harnessFail('HARNESS_INPUT_INVALID', 'PRNG shuffle input must be a dense inert array');
    return Array.from({ length: values.length }, (_, index) => {
      const descriptor = descriptors[String(index)];
      if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) harnessFail('HARNESS_INPUT_INVALID', 'PRNG shuffle input cannot contain accessors or hidden elements');
      return descriptor.value;
    });
  } catch (error) {
    if (error?.code?.startsWith?.('HARNESS_')) throw error;
    harnessFail('HARNESS_INPUT_INVALID', 'PRNG shuffle input could not be inspected safely', { cause: error });
  }
}

export class DeterministicRandom {
  #seed;
  #counter = 0n;
  #pool = Buffer.alloc(0);
  #offset = 0;
  constructor(seed) { this.#seed = seedBytes(seed); }
  #refill() {
    const counter = Buffer.alloc(8);
    counter.writeBigUInt64BE(this.#counter);
    this.#counter += 1n;
    this.#pool = createHash('sha256').update(this.#seed).update(counter).digest();
    this.#offset = 0;
  }
  bytes(length) {
    if (!Number.isSafeInteger(length) || length < 0 || length > 1024 * 1024) harnessFail('HARNESS_INPUT_INVALID', 'PRNG byte request is invalid');
    const output = Buffer.alloc(length);
    for (let index = 0; index < length; index += 1) {
      if (this.#offset >= this.#pool.length) this.#refill();
      output[index] = this.#pool[this.#offset++];
    }
    return output;
  }
  integer(maximumExclusive) {
    if (!Number.isSafeInteger(maximumExclusive) || maximumExclusive < 1 || maximumExclusive > 0x1_0000_0000) harnessFail('HARNESS_INPUT_INVALID', 'PRNG integer bound is invalid');
    const range = 0x1_0000_0000;
    const ceiling = range - (range % maximumExclusive);
    while (true) {
      const value = this.bytes(4).readUInt32BE(0);
      if (value < ceiling) return value % maximumExclusive;
    }
  }
  shuffle(values) {
    const output = inertArray(values);
    for (let index = output.length - 1; index > 0; index -= 1) {
      const selected = this.integer(index + 1);
      [output[index], output[selected]] = [output[selected], output[index]];
    }
    return output;
  }
}
