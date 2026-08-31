import { transferError } from './errors.mjs';

const SHA = /^[0-9a-f]{64}$/u;
const REQUIRED_METHODS = Object.freeze([
  'createIfAbsent',
  'head',
  'initialize',
  'listByInternalPrefix',
  'readRange',
  'readVerifiedRange',
  'safeDelete',
  'verify',
]);
const CAPABILITY_KEYS = [
  'backendKind',
  'boundedPrefixList',
  'createIfAbsent',
  'exactMetadata',
  'generationFencedDelete',
  'multipartEtagIsDigest',
  'objectBytesMaximum',
  'profile',
  'rangeBytesMaximum',
  'schemaVersion',
  'verifiedRanges',
  'wholeObjectVerification',
].sort().join('\0');

function exactCapabilities(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).sort().join('\0') !== CAPABILITY_KEYS
      || value.schemaVersion !== 'ogvcs.object-transfer/backend-capabilities/v1'
      || !['filesystem', 's3-compatible'].includes(value.backendKind)
      || typeof value.profile !== 'string' || value.profile.length < 1 || value.profile.length > 128
      || !Number.isSafeInteger(value.objectBytesMaximum) || value.objectBytesMaximum < 1
      || value.objectBytesMaximum > 67_108_864
      || !Number.isSafeInteger(value.rangeBytesMaximum) || value.rangeBytesMaximum < 1
      || value.rangeBytesMaximum > value.objectBytesMaximum
      || value.createIfAbsent !== true || value.exactMetadata !== true
      || value.wholeObjectVerification !== true || value.verifiedRanges !== true
      || value.boundedPrefixList !== true || value.generationFencedDelete !== true
      // An ETag is an opaque conditional-write token. Multipart ETags are not
      // content digests and adapters are forbidden from advertising otherwise.
      || value.multipartEtagIsDigest !== false) {
    transferError('TRANSFER_INPUT_INVALID', 'backend capability profile is invalid');
  }
  return Object.freeze({ ...value });
}

// Each adapter stores this captured record in a module-private WeakMap. There
// is deliberately no shared registration map a deep importer could populate.
export function captureTrustedBackend(instance, capabilities, definition) {
  if (!instance || (typeof instance !== 'object' && typeof instance !== 'function')
      || !definition || typeof definition !== 'object'
      || Object.keys(definition).sort().join('\0') !== 'constructor\0methods\0prototype'
      || definition.constructor !== definition.prototype?.constructor
      || Object.getPrototypeOf(instance) !== definition.prototype
      || !Object.isFrozen(definition.prototype)
      || !Object.isFrozen(definition.methods)
      || Object.keys(definition.methods).sort().join('\0') !== [...REQUIRED_METHODS].sort().join('\0')
      || REQUIRED_METHODS.some((method) => {
        const descriptor = Object.getOwnPropertyDescriptor(definition.prototype, method);
        return Object.hasOwn(instance, method) || typeof definition.methods[method] !== 'function'
          || descriptor?.value !== definition.methods[method]
          || descriptor.writable !== false || descriptor.configurable !== false;
      })) {
    transferError('TRANSFER_INPUT_INVALID', 'trusted backend adapter is invalid');
  }
  const exact = exactCapabilities(capabilities);
  // Capture package-owned methods while the exact adapter constructor is
  // running. Service dispatch never consults mutable own/prototype properties
  // on the caller-visible instance after this point.
  const port = Object.freeze(Object.fromEntries(REQUIRED_METHODS.map((method) => [
    method,
    definition.methods[method].bind(instance),
  ])));
  return Object.freeze({ capabilities: exact, port });
}

export function validateOpaqueBackendKey(value) {
  if (typeof value !== 'string' || !SHA.test(value)) {
    transferError('TRANSFER_INPUT_INVALID', 'opaque backend key is invalid');
  }
  return value;
}
