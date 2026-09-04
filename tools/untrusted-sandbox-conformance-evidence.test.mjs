import assert from 'node:assert/strict';
import { readFile, stat } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import test from 'node:test';

import {
  SANDBOX_CONFORMANCE_SOURCE_PATHS,
  snapshotSourceEvidence,
} from '../core/untrusted-sandbox/js/src/internal/conformance-evidence.mjs';
import { sha256 } from '../core/untrusted-sandbox/js/src/internal/reference-contract.mjs';

const root = resolve(import.meta.dirname, '..');

test('source-only conformance inventory is frozen, sorted, unique, present, and bounded', async () => {
  assert.equal(Object.isFrozen(SANDBOX_CONFORMANCE_SOURCE_PATHS), true);
  assert.deepEqual(SANDBOX_CONFORMANCE_SOURCE_PATHS, [...SANDBOX_CONFORMANCE_SOURCE_PATHS].sort());
  assert.equal(new Set(SANDBOX_CONFORMANCE_SOURCE_PATHS).size, SANDBOX_CONFORMANCE_SOURCE_PATHS.length);
  const sourceFiles = [];
  for (const path of SANDBOX_CONFORMANCE_SOURCE_PATHS) {
    const details = await stat(join(root, path));
    assert.equal(details.isFile(), true, path);
    assert.ok(details.size <= 16 * 1024 * 1024, path);
    const bytes = await readFile(join(root, path));
    sourceFiles.push({ bytes: bytes.length, path, sha256: sha256(bytes) });
  }
  const evidence = snapshotSourceEvidence({ sourceFiles, sourceRevision: '1'.repeat(40) });
  assert.equal(evidence.sourceFiles.length, SANDBOX_CONFORMANCE_SOURCE_PATHS.length);
  assert.match(evidence.sourceSetSha256, /^[0-9a-f]{64}$/u);
});

test('source-only generators have no upload, dispatch, or public-admission channel', async () => {
  for (const path of [
    'core/untrusted-sandbox/js/scripts/portable-conformance.mjs',
    'core/untrusted-sandbox/js/scripts/source-model-conformance.mjs',
    'core/untrusted-sandbox/js/scripts/kill-boundary-conformance.mjs',
    'tools/compare-untrusted-sandbox-conformance.mjs',
  ]) {
    const source = await readFile(join(root, path), 'utf8');
    assert.doesNotMatch(source, /actions\/upload-artifact|workflow_dispatch|repository_dispatch|\bfetch\s*\(|https?:\/\//u, path);
  }
});
