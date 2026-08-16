import assert from 'node:assert/strict';
import test from 'node:test';
import { validateBundleClaim } from '../src/bundle.js';
import { OgvcsError } from '../src/errors.js';
import { validateFileIdAllocation } from '../src/fileid.js';
import { Digest } from '../src/types.js';

const code = expected => error => error instanceof OgvcsError && error.code === expected;

test('supplied closure cannot be relabelled as fidelity or projection export', () => {
  assert.equal(validateBundleClaim('supplied-closure'), 'supplied-closure');
  assert.throws(() => validateBundleClaim('fidelity-export'), code('BUNDLE_EXPORT_CLAIM_FORBIDDEN'));
  assert.throws(() => validateBundleClaim('authorized-projection'), code('BUNDLE_EXPORT_CLAIM_FORBIDDEN'));
  assert.throws(() => validateBundleClaim(''), code('SCHEMA_FIELD_INVALID'));
});

test('allocation finalize rejects a concurrent winner without mutating evidence', () => {
  const request = {
    schema: 'ogvcs.repository-format.v1.fileid-operation-input.v1',
    operation: 'allocate-file-id',
    candidateFileId: '21212121212121212121212121212121',
    retryLimit: 1
  };
  const workingLifetimeAdditions = [{ fileId: request.candidateFileId }];
  const before = structuredClone(workingLifetimeAdditions);
  assert.throws(
    () => validateFileIdAllocation(request, { workingLifetimeAdditions }),
    code('FILEID_ALLOCATION_COLLISION')
  );
  assert.deepEqual(workingLifetimeAdditions, before);
  const accepted = validateFileIdAllocation(
    { ...request, candidateFileId: '22222222222222222222222222222222' },
    { workingLifetimeAdditions }
  );
  assert.equal(accepted.fileId, 'fid:22222222222222222222222222222222');
});

test('allocation validation streams lifetime collections without eager concatenation', () => {
  const request = {
    schema: 'ogvcs.repository-format.v1.fileid-operation-input.v1',
    operation: 'allocate-file-id',
    candidateFileId: '21212121212121212121212121212121',
    retryLimit: 1
  };
  const later = [];
  let laterIteratorRead = false;
  Object.defineProperty(later, Symbol.iterator, {
    get() { laterIteratorRead = true; throw new Error('later collection must remain unread'); }
  });
  assert.throws(() => validateFileIdAllocation(request, {
    lifetimeRecords: [{ fileId: request.candidateFileId }],
    workingLifetimeAdditions: later
  }), code('FILEID_ALLOCATION_COLLISION'));
  assert.equal(laterIteratorRead, false);
  assert.throws(() => validateFileIdAllocation(request, {
    lifetimeRecords: [{ fileId: '22222222222222222222222222222222' }],
    maxLifetimeRecords: 0
  }), error => error instanceof OgvcsError && error.code === 'LIMIT_COUNT' &&
    error.stage === 'configured-resource-preflight');
});

test('TypedDigest reserves ObjectRef format errors for ObjectRef values', () => {
  assert.throws(() => Digest.fromMap(new Map([[0, 2], [1, new Uint8Array(32)]])), code('SCHEMA_FIELD_INVALID'));
});
