import { filesystemBackendRecord } from './backend.mjs';
import { transferError } from './errors.mjs';
import { s3BackendRecord } from './s3-backend.mjs';

function record(instance) {
  const trusted = filesystemBackendRecord(instance) ?? s3BackendRecord(instance);
  if (!trusted) {
    transferError('TRANSFER_INPUT_INVALID', 'transfer backend must be constructed by a trusted adapter');
  }
  return trusted;
}

export function backendCapabilities(instance) {
  return record(instance).capabilities;
}

export function trustedBackendPort(instance) {
  return record(instance).port;
}
