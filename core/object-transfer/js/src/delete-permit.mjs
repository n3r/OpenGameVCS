import { randomBytes } from 'node:crypto';
import { transferError } from './errors.mjs';

const DELETE_PERMIT = Symbol('ogvcs.object-transfer/delete-permit');
const REUPLOAD_PERMIT = Symbol('ogvcs.object-transfer/reupload-permit');
const CONSUMED = new WeakSet();
const REUPLOAD_CONSUMED = new WeakSet();
const SHA = /^[0-9a-f]{64}$/u;
const TOKEN = /^[0-9a-f]{48}$/u;
const KEYS = [
  'authorityBindingSha256',
  'expectedGeneration',
  'length',
  'objectId',
  'opaqueKey',
  'permitToken',
  'priorReceiptSha256',
  'schemaVersion',
].sort().join('\0');
const REUPLOAD_KEYS = [
  'deletionReceiptSha256',
  'expectedDeletedGeneration',
  'length',
  'nextAuthorityBindingSha256',
  'objectId',
  'opaqueKey',
  'permitToken',
  'priorAuthorityBindingSha256',
  'schemaVersion',
].sort().join('\0');

function fields(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || value[DELETE_PERMIT] !== true || Object.keys(value).sort().join('\0') !== KEYS
      || value.schemaVersion !== 'ogvcs.object-transfer/delete-permit/v1'
      || !SHA.test(value.opaqueKey ?? '') || !SHA.test(value.priorReceiptSha256 ?? '')
      || !SHA.test(value.authorityBindingSha256 ?? '') || !TOKEN.test(value.permitToken ?? '')
      || typeof value.objectId !== 'string' || value.objectId.length < 1 || value.objectId.length > 144
      || !Number.isSafeInteger(value.length) || value.length < 0 || value.length > 67_108_864
      || !Number.isSafeInteger(value.expectedGeneration) || value.expectedGeneration < 1) {
    transferError('TRANSFER_LIFECYCLE_STALE', 'authoritative deleting-generation permit is invalid');
  }
  return value;
}

function reuploadFields(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || value[REUPLOAD_PERMIT] !== true || Object.keys(value).sort().join('\0') !== REUPLOAD_KEYS
      || value.schemaVersion !== 'ogvcs.object-transfer/reupload-permit/v1'
      || !SHA.test(value.opaqueKey ?? '') || !SHA.test(value.deletionReceiptSha256 ?? '')
      || !SHA.test(value.priorAuthorityBindingSha256 ?? '')
      || !SHA.test(value.nextAuthorityBindingSha256 ?? '') || !TOKEN.test(value.permitToken ?? '')
      || typeof value.objectId !== 'string' || value.objectId.length < 1 || value.objectId.length > 144
      || !Number.isSafeInteger(value.length) || value.length < 0 || value.length > 67_108_864
      || !Number.isSafeInteger(value.expectedDeletedGeneration) || value.expectedDeletedGeneration < 2) {
    transferError('TRANSFER_LIFECYCLE_STALE', 'authoritative deleted-generation reupload permit is invalid');
  }
  return value;
}

export function issueDeletePermit({
  opaqueKey,
  objectId,
  length,
  priorReceiptSha256,
  expectedGeneration,
  authorityBindingSha256,
}) {
  const permit = {
    schemaVersion: 'ogvcs.object-transfer/delete-permit/v1',
    opaqueKey,
    objectId,
    length,
    priorReceiptSha256,
    expectedGeneration,
    authorityBindingSha256,
    permitToken: randomBytes(24).toString('hex'),
  };
  Object.defineProperty(permit, DELETE_PERMIT, { value: true });
  return Object.freeze(fields(permit));
}

export function consumeDeletePermit(value) {
  const permit = fields(value);
  if (CONSUMED.has(permit)) {
    transferError('TRANSFER_LIFECYCLE_STALE', 'authoritative deleting-generation permit was already consumed');
  }
  CONSUMED.add(permit);
  const { permitToken: _permitToken, ...durableFields } = permit;
  return Object.freeze(durableFields);
}

export function assertDeletePermitConsumed(value) {
  const permit = fields(value);
  if (!CONSUMED.has(permit)) {
    transferError('TRANSFER_LIFECYCLE_STALE', 'authoritative deleting-generation permit was not consumed by the backend');
  }
}

export function issueReuploadPermit({
  opaqueKey,
  objectId,
  length,
  expectedDeletedGeneration,
  deletionReceiptSha256,
  priorAuthorityBindingSha256,
  nextAuthorityBindingSha256,
}) {
  const permit = {
    schemaVersion: 'ogvcs.object-transfer/reupload-permit/v1',
    opaqueKey,
    objectId,
    length,
    expectedDeletedGeneration,
    deletionReceiptSha256,
    priorAuthorityBindingSha256,
    nextAuthorityBindingSha256,
    permitToken: randomBytes(24).toString('hex'),
  };
  Object.defineProperty(permit, REUPLOAD_PERMIT, { value: true });
  return Object.freeze(reuploadFields(permit));
}

export function consumeReuploadPermit(value) {
  const permit = reuploadFields(value);
  if (REUPLOAD_CONSUMED.has(permit)) {
    transferError('TRANSFER_LIFECYCLE_STALE', 'authoritative deleted-generation reupload permit was already consumed');
  }
  REUPLOAD_CONSUMED.add(permit);
  const { permitToken: _permitToken, ...durableFields } = permit;
  return Object.freeze(durableFields);
}

export function assertReuploadPermitConsumed(value) {
  const permit = reuploadFields(value);
  if (!REUPLOAD_CONSUMED.has(permit)) {
    transferError('TRANSFER_LIFECYCLE_STALE', 'authoritative deleted-generation reupload permit was not consumed by the backend');
  }
}
