import { transferError } from './errors.mjs';

const PORTS = new WeakMap();
const REQUIRED_METHODS = Object.freeze([
  'compareAndSwap',
  'createStaged',
  'deleteAuthorized',
  'get',
  'initialize',
  'issueReuploadPermit',
  'listBounded',
  'receipt',
  'recordReverifiedDeleted',
]);
const CAPABILITY_KEYS = [
  'atomicWithRepositoryMetadata',
  'generationFenced',
  'lifecycleContractVersion',
  'receiptGatedContentManifest',
  'schemaVersion',
  'storageAuthority',
].sort().join('\0');

function exactCapabilities(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).sort().join('\0') !== CAPABILITY_KEYS
      || value.schemaVersion !== 'ogvcs.object-transfer/lifecycle-adapter-capabilities/v1'
      || !['filesystem-local-candidate', 'repository-metadata'].includes(value.storageAuthority)
      || typeof value.lifecycleContractVersion !== 'string'
      || !/^[A-Za-z0-9._/@-]{1,128}$/u.test(value.lifecycleContractVersion)
      || typeof value.atomicWithRepositoryMetadata !== 'boolean'
      || value.generationFenced !== true || value.receiptGatedContentManifest !== true
      || (value.storageAuthority === 'filesystem-local-candidate' && value.atomicWithRepositoryMetadata !== false)
      || (value.storageAuthority === 'repository-metadata' && value.atomicWithRepositoryMetadata !== true)) {
    transferError('TRANSFER_INPUT_INVALID', 'lifecycle adapter capability profile is invalid');
  }
  return Object.freeze({ ...value });
}

// This is the explicit integration seam for the separately owned repository-
// metadata lifecycle lane. Calling it is an affirmative adapter construction;
// ObjectTransferService never accepts a merely structural lifecycle object.
// The captured port is immutable and does not dispatch through mutable adapter
// properties after construction.
export function createLifecycleAdapterPort({ adapter, capabilities } = {}) {
  if (!adapter || (typeof adapter !== 'object' && typeof adapter !== 'function')
      || REQUIRED_METHODS.some((method) => typeof adapter[method] !== 'function')) {
    transferError('TRANSFER_INPUT_INVALID', 'lifecycle adapter is invalid');
  }
  const exact = exactCapabilities(capabilities);
  const port = Object.freeze(Object.fromEntries(REQUIRED_METHODS.map((method) => [
    method,
    adapter[method].bind(adapter),
  ])));
  const record = Object.freeze({ capabilities: exact, port });
  PORTS.set(port, record);
  return port;
}

export function lifecycleAdapterCapabilities(port) {
  const record = PORTS.get(port);
  if (!record) transferError('TRANSFER_INPUT_INVALID', 'lifecycle adapter port was not explicitly constructed');
  return record.capabilities;
}

export function trustedLifecycleAdapterPort(port) {
  const record = PORTS.get(port);
  if (!record) transferError('TRANSFER_INPUT_INVALID', 'lifecycle adapter port was not explicitly constructed');
  return record.port;
}
