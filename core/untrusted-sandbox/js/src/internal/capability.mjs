import { types } from 'node:util';

const REQUIRED = Object.freeze(['cpuLimited', 'credentialFree', 'isolatedScratch', 'memoryLimited', 'networkDenied', 'processLimited', 'readOnlyInput']);
export const REFERENCE_SERVICE_HARD_KILL_BOUNDARIES = Object.freeze([
  'after-admission',
  'after-acquisition-state',
  'after-input-stage',
  'after-stage',
  'after-running-state',
  'after-worker',
  'after-validating-state',
  'after-output-collection',
  'after-validation',
  'after-committing-state',
  'before-output-commit',
  'after-output-commit',
  'after-result-commit',
]);
const capabilities = new WeakSet();
const referenceServiceTestHooks = new WeakMap();
const controls = (source) => {
  if (source === null || typeof source !== 'object' || Array.isArray(source) || types.isProxy(source)) return null;
  try {
    const prototype = Object.getPrototypeOf(source);
    if (prototype !== Object.prototype && prototype !== null) return null;
    const descriptors = Object.getOwnPropertyDescriptors(source);
    if (Object.keys(descriptors).sort().join(',') !== REQUIRED.join(',')) return null;
    if (REQUIRED.some((key) => !Object.hasOwn(descriptors[key], 'value') || typeof descriptors[key].value !== 'boolean' || Object.hasOwn(descriptors[key], 'get') || Object.hasOwn(descriptors[key], 'set'))) return null;
    return Object.freeze(Object.fromEntries(REQUIRED.map((key) => [key, descriptors[key].value])));
  } catch { return null; }
};
export const createTestingLauncherCapability = ({ assertedControls, launch }) => {
  const snapshot = controls(assertedControls);
  if (!snapshot || typeof launch !== 'function' || types.isProxy(launch)) throw new TypeError('testing launcher capability is invalid');
  const capability = Object.freeze({ launch, assertedControls: snapshot }); capabilities.add(capability); return capability;
};
export const candidateLauncherParts = (capability) => capabilities.has(capability) ? capability : null;

export const createReferenceServiceTestHookCapability = (hook) => {
  if (typeof hook !== 'function' || types.isProxy(hook)) throw new TypeError('reference service test hook is invalid');
  const capability = Object.freeze({});
  referenceServiceTestHooks.set(capability, hook);
  return capability;
};

export const referenceServiceTestHook = (capability) => referenceServiceTestHooks.get(capability) ?? null;
