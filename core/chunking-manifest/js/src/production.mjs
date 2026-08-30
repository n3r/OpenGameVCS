import { ProfileRef, decodeMetadata, profileDecision } from '@opengamevcs/object-model';
import { createOperationControl } from './control.mjs';
import { fail, normalizeError } from './errors.mjs';
import { PROFILE } from './identity.mjs';
import { consumeVerificationReceipt, VERIFICATION_RECEIPT_VERIFIER } from './receipt.mjs';
import { parseManifestReceiptRequirements } from './verify.mjs';

export const PRODUCTION_BOUNDARY_VERSION = 'ogvcs.chunking-manifest/production-boundary@1';
const PROFILE_TEXT = `${PROFILE.namespace}/${PROFILE.id}@${PROFILE.major}`;
const PROFILE_REF = new ProfileRef(PROFILE.namespace, PROFILE.id, PROFILE.major);

const DEFAULT_MANIFEST_BYTES = 64 * 1024 * 1024;

function boundedManifest(input) {
  const maximum = input.maxManifestBytes ?? DEFAULT_MANIFEST_BYTES;
  const selected = input.manifest?.bytes ?? input.manifest;
  if (!Number.isSafeInteger(maximum) || maximum < 0
      || !(selected instanceof Uint8Array) || selected.byteLength > maximum) {
    fail('CHUNK_MANIFEST_MISMATCH');
  }
  return Buffer.from(selected);
}

function requireProductionAuthority(registry, manifest, input) {
  let entry;
  try {
    // This public OGVCS-002 operation requires its privately branded complete
    // RegistrySnapshot. A caller-shaped map or partial RegistrySnapshot cannot
    // cross the production boundary even if it contains a plausible row.
    decodeMetadata(manifest, {
      registry,
      operation: 'production-write',
      maxBytes: input.maxManifestBytes ?? DEFAULT_MANIFEST_BYTES,
      maxWorkingBytes: Math.min(input.maxDecodeWorkingBytes ?? DEFAULT_MANIFEST_BYTES, DEFAULT_MANIFEST_BYTES),
    });
    entry = profileDecision(registry, PROFILE_REF, 'production-write');
  } catch (cause) {
    throw normalizeError(cause, 'CHUNK_PROFILE_UNSUPPORTED');
  }
  if (entry.family !== 'chunking' || entry.owner !== 'OGVCS-007' || entry.state !== 'ratified'
      || entry.productionWriteAllowed !== true) {
    fail('CHUNK_PROFILE_UNSUPPORTED');
  }
  return entry;
}

function requirePublication(publication) {
  if (!publication || typeof publication !== 'object'
      || typeof publication.write !== 'function'
      || typeof publication.commit !== 'function'
      || typeof publication.abort !== 'function') {
    fail('CHUNK_RESOURCE_INVALID');
  }
  return publication;
}

/**
 * Cross the production trust boundary only after exact profile verification.
 *
 * The caller owns the durable transaction, but cannot receive manifest bytes or
 * a commit callback from this boundary until the complete, branded one-use
 * verifier receipt and the production registry lifecycle decision both pass.
 */
export async function commitProductionManifest(input = {}) {
  let control;
  let publication;
  let transactionOpen = false;
  try {
    publication = requirePublication(input.publication);
    control = createOperationControl(input);
    control.check();
    const manifest = boundedManifest(input);
    const requirements = parseManifestReceiptRequirements(manifest, input);
    requireProductionAuthority(input.registry, manifest, input);
    consumeVerificationReceipt(input.verificationReceipt, {
      verifier: VERIFICATION_RECEIPT_VERIFIER,
      profile: PROFILE_TEXT,
      manifest,
      manifestObjectId: requirements.manifestObjectId,
      manifestSha256: requirements.manifestSha256,
      logicalBytes: requirements.logicalBytes,
      wholeFileSha256: requirements.wholeFileSha256,
      workspacePublication: input.workspacePublication,
    }, 'CHUNK_PUBLICATION_FAILED');

    const context = Object.freeze({
      ...control.context,
      boundary: PRODUCTION_BOUNDARY_VERSION,
      verifier: VERIFICATION_RECEIPT_VERIFIER,
      profile: PROFILE_TEXT,
      manifestObjectId: requirements.manifestObjectId,
      manifestSha256: requirements.manifestSha256,
      logicalBytes: requirements.logicalBytes,
      wholeFileSha256: requirements.wholeFileSha256,
      workspacePublication: input.workspacePublication,
    });
    transactionOpen = true;
    await Promise.resolve().then(() => publication.write(Buffer.from(manifest), context));
    control.check();
    const publicationResult = await Promise.resolve().then(() => publication.commit(context));
    transactionOpen = false;
    return Object.freeze({
      boundary: PRODUCTION_BOUNDARY_VERSION,
      verifier: VERIFICATION_RECEIPT_VERIFIER,
      profile: PROFILE_TEXT,
      manifestObjectId: requirements.manifestObjectId,
      manifestSha256: requirements.manifestSha256,
      logicalBytes: requirements.logicalBytes,
      wholeFileSha256: requirements.wholeFileSha256,
      publicationResult,
    });
  } catch (cause) {
    const error = normalizeError(cause, 'CHUNK_PUBLICATION_FAILED');
    if (transactionOpen) {
      transactionOpen = false;
      try { await Promise.resolve(publication.abort(error)); } catch {}
    }
    throw error;
  } finally {
    control?.dispose();
  }
}
