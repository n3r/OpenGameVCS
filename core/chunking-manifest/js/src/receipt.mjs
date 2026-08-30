import { createHash } from 'node:crypto';
import { fail } from './errors.mjs';

export const VERIFICATION_RECEIPT_VERIFIER = 'ogvcs.chunking-manifest/verifier@1';
const RECEIPT_STATE = new WeakMap();

function manifestSha256Hex(manifest) {
  return createHash('sha256').update(manifest).digest('hex');
}

function optionalExact(expected, actual, field, code) {
  if (expected !== undefined && expected !== actual) fail(code, { field });
}

export function createVerificationReceipt(details) {
  const payload = Object.freeze({
    verifier: details.verifier ?? VERIFICATION_RECEIPT_VERIFIER,
    profile: details.profile,
    manifestObjectId: details.manifestObjectId,
    manifestSha256: details.manifestSha256,
    logicalBytes: details.logicalBytes,
    wholeFileSha256: details.wholeFileSha256,
    workspacePublication: details.workspacePublication,
  });
  const receipt = Object.freeze({ ...payload });
  RECEIPT_STATE.set(receipt, { payload, used: false });
  return receipt;
}

export function consumeVerificationReceipt(receipt, requirements = {}, code = 'CHUNK_RESOURCE_INVALID') {
  const state = RECEIPT_STATE.get(receipt);
  if (state === undefined || state.used) fail(code, { resource: 'verificationReceipt' });
  const { payload } = state;
  optionalExact(requirements.verifier, payload.verifier, 'verifier', code);
  optionalExact(requirements.profile, payload.profile, 'profile', code);
  optionalExact(requirements.manifestObjectId, payload.manifestObjectId, 'manifestObjectId', code);
  if (requirements.manifest !== undefined) {
    optionalExact(manifestSha256Hex(requirements.manifest), payload.manifestSha256, 'manifestSha256', code);
  }
  optionalExact(requirements.manifestSha256, payload.manifestSha256, 'manifestSha256', code);
  optionalExact(requirements.logicalBytes, payload.logicalBytes, 'logicalBytes', code);
  optionalExact(requirements.wholeFileSha256, payload.wholeFileSha256, 'wholeFileSha256', code);
  if (requirements.workspacePublication !== undefined) {
    const expected = requirements.workspacePublication;
    const actual = payload.workspacePublication;
    if (!actual || expected.path !== actual.path || expected.bytes !== actual.bytes
      || expected.sha256 !== actual.sha256 || expected.transaction !== actual.transaction) {
      fail(code, { field: 'workspacePublication' });
    }
  }
  state.used = true;
  return payload;
}
