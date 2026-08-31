import { types } from 'node:util';

const REQUIRED = Object.freeze(['cpuLimited', 'credentialFree', 'isolatedScratch', 'memoryLimited', 'networkDenied', 'processLimited', 'readOnlyInput']);
const capabilities = new WeakSet();
const controls = (source) => {
  if (source === null || typeof source !== 'object' || Array.isArray(source) || types.isProxy(source)) return null;
  try {
    const descriptors = Object.getOwnPropertyDescriptors(source);
    if (Object.keys(descriptors).sort().join(',') !== REQUIRED.join(',')) return null;
    if (REQUIRED.some((key) => !Object.hasOwn(descriptors[key], 'value') || typeof descriptors[key].value !== 'boolean' || Object.hasOwn(descriptors[key], 'get') || Object.hasOwn(descriptors[key], 'set'))) return null;
    return Object.freeze(Object.fromEntries(REQUIRED.map((key) => [key, descriptors[key].value])));
  } catch { return null; }
};
export const createTestingLauncherCapability = ({ assertedControls, launch }) => {
  const snapshot = controls(assertedControls);
  if (!snapshot || typeof launch !== 'function') throw new TypeError('testing launcher capability is invalid');
  const capability = Object.freeze({ launch, assertedControls: snapshot }); capabilities.add(capability); return capability;
};
export const candidateLauncherParts = (capability) => capabilities.has(capability) ? capability : null;
