import { types as utilTypes } from 'node:util';

import { cloneData } from './canonical.mjs';
import { harnessFail } from './errors.mjs';

const MAX_OPTION_FIELDS = 256;

export function snapshotOptions(input, label = 'options') {
  if (input === undefined) return Object.create(null);
  try {
    if (input === null || typeof input !== 'object' || Array.isArray(input) || utilTypes.isProxy(input)) throw new TypeError(`${label} must be a plain inert record`);
    const prototype = Object.getPrototypeOf(input);
    const keys = Reflect.ownKeys(input);
    const descriptors = Object.getOwnPropertyDescriptors(input);
    if (prototype !== Object.prototype && prototype !== null || keys.length > MAX_OPTION_FIELDS || keys.some((key) => typeof key !== 'string')) throw new TypeError(`${label} must be a bounded plain inert record`);
    const output = Object.create(null);
    for (const key of keys) {
      const descriptor = descriptors[key];
      if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) throw new TypeError(`${label} cannot contain accessors or hidden properties`);
      Object.defineProperty(output, key, { configurable: true, enumerable: true, value: descriptor.value, writable: true });
    }
    return output;
  } catch (error) {
    harnessFail('HARNESS_INPUT_INVALID', `${label} could not be inspected without executing caller code`, { cause: error });
  }
}

export function snapshotData(input, label = 'input') {
  try { return cloneData(input); }
  catch (error) { harnessFail('HARNESS_INPUT_INVALID', `${label} must be bounded inert canonical data`, { cause: error }); }
}

export function snapshotArray(input, label = 'array', maximum = Number.MAX_SAFE_INTEGER) {
  try {
    if (!Array.isArray(input) || utilTypes.isProxy(input) || Object.getPrototypeOf(input) !== Array.prototype || input.length > maximum) throw new TypeError(`${label} must be a bounded inert array`);
    const keys = Reflect.ownKeys(input);
    const descriptors = Object.getOwnPropertyDescriptors(input);
    if (keys.some((key) => typeof key !== 'string') || keys.length !== input.length + 1 || !keys.includes('length')) throw new TypeError(`${label} must be a dense inert array`);
    return Array.from({ length: input.length }, (_, index) => {
      const descriptor = descriptors[String(index)];
      if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) throw new TypeError(`${label} cannot contain accessors or hidden elements`);
      return descriptor.value;
    });
  } catch (error) {
    harnessFail('HARNESS_INPUT_INVALID', `${label} could not be inspected without executing caller code`, { cause: error });
  }
}
