import { randomBytes } from 'node:crypto';
import { fail, OgvcsError } from './errors.js';
import { FileId, toHex } from './types.js';

export const MAX_FILE_ID_ALLOCATION_ATTEMPTS = 1_024;

function requestFileId(value) {
  if (value instanceof FileId) return value;
  if (typeof value !== 'string' || !/^[0-9a-f]{32}$/.test(value)) {
    fail('SCHEMA_FIELD_INVALID', { layer: 2 });
  }
  return FileId.parse(`fid:${value}`);
}

function consumedFileId(value) {
  if (value instanceof FileId) return value.toString();
  if (typeof value === 'string') {
    return FileId.parse(value.startsWith('fid:') ? value : `fid:${value}`).toString();
  }
  if (value && Object.hasOwn(value, 'fileId')) return consumedFileId(value.fileId);
  fail('SCHEMA_FIELD_INVALID', { layer: 2 });
}

function operatingSystemEntropy() {
  try { return new Uint8Array(randomBytes(16)); }
  catch (cause) { fail('FILEID_ENTROPY_UNAVAILABLE', { cause, layer: 3 }); }
}

export async function allocateFileId({ entropy = operatingSystemEntropy, isConsumed = () => false, maxAttempts = 32 } = {}) {
  if (typeof entropy !== 'function' || typeof isConsumed !== 'function' || !Number.isInteger(maxAttempts) ||
      maxAttempts < 1 || maxAttempts > MAX_FILE_ID_ALLOCATION_ATTEMPTS) {
    fail('SCHEMA_FIELD_INVALID', { layer: 2 });
  }
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    let candidate;
    try { candidate = await entropy(); }
    catch (cause) {
      if (cause instanceof OgvcsError) throw cause;
      fail('FILEID_ENTROPY_UNAVAILABLE', { cause, layer: 3 });
    }
    if (!(candidate instanceof Uint8Array) || candidate.length !== 16) {
      fail('FILEID_ENTROPY_UNAVAILABLE', { layer: 3 });
    }
    if (candidate.every(byte => byte === 0)) continue;
    if (await isConsumed(candidate.slice(), toHex(candidate))) continue;
    return new FileId(candidate);
  }
  fail('FILEID_ALLOCATION_EXHAUSTED', { layer: 3 });
}

/**
 * Pure compare-and-finalize preflight for a caller-selected FileID reservation.
 * The supplied lifetime collections are observations only and are never
 * mutated. A concurrent winner is reported distinctly from CSPRNG retry
 * exhaustion.
 */
export function validateFileIdAllocation(request, {
  lifetimeRecords = [], workingLifetimeAdditions = [],
  maxLifetimeRecords = Number.MAX_SAFE_INTEGER, checkpoint = () => {}
} = {}) {
  if (!request || request.schema !== 'ogvcs.repository-format.v1.fileid-operation-input.v1' ||
      request.operation !== 'allocate-file-id' ||
      Object.keys(request).some(key => !['schema', 'operation', 'candidateFileId', 'retryLimit'].includes(key)) ||
      !Number.isInteger(request.retryLimit) || request.retryLimit < 1 ||
      request.retryLimit > MAX_FILE_ID_ALLOCATION_ATTEMPTS ||
      !Array.isArray(lifetimeRecords) || !Array.isArray(workingLifetimeAdditions) ||
      !Number.isSafeInteger(maxLifetimeRecords) || maxLifetimeRecords < 0 || typeof checkpoint !== 'function') {
    fail('SCHEMA_FIELD_INVALID', { layer: 2 });
  }
  const candidate = requestFileId(request.candidateFileId);
  const key = candidate.toString();
  let records = 0;
  for (const collection of [lifetimeRecords, workingLifetimeAdditions]) {
    for (const record of collection) {
      records += 1;
      if (records > maxLifetimeRecords) fail('LIMIT_COUNT', {
        layer: 1, stage: 'configured-resource-preflight'
      });
      checkpoint();
      if (consumedFileId(record) === key) fail('FILEID_ALLOCATION_COLLISION', { layer: 3 });
    }
  }
  return Object.freeze({ fileId: key, retryLimit: request.retryLimit });
}
