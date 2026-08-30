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
  state.used = true;
  const { payload } = state;
  const verifier = requirements.verifier;
  const profile = requirements.profile;
  const manifestObjectId = requirements.manifestObjectId;
  const manifest = requirements.manifest;
  const manifestSha256 = requirements.manifestSha256;
  const logicalBytes = requirements.logicalBytes;
  const wholeFileSha256 = requirements.wholeFileSha256;
  const workspacePublication = requirements.workspacePublication;
  optionalExact(verifier, payload.verifier, 'verifier', code);
  optionalExact(profile, payload.profile, 'profile', code);
  optionalExact(manifestObjectId, payload.manifestObjectId, 'manifestObjectId', code);
  if (manifest !== undefined) {
    optionalExact(manifestSha256Hex(manifest), payload.manifestSha256, 'manifestSha256', code);
  }
  optionalExact(manifestSha256, payload.manifestSha256, 'manifestSha256', code);
  optionalExact(logicalBytes, payload.logicalBytes, 'logicalBytes', code);
  optionalExact(wholeFileSha256, payload.wholeFileSha256, 'wholeFileSha256', code);
  if (workspacePublication !== undefined) {
    const expected = workspacePublication;
    const actual = payload.workspacePublication;
    if (!actual || expected.path !== actual.path || expected.bytes !== actual.bytes
      || expected.sha256 !== actual.sha256 || expected.transaction !== actual.transaction) {
      fail(code, { field: 'workspacePublication' });
    }
  }
  return payload;
}
