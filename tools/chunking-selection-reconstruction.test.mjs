import assert from 'node:assert/strict';
import test from 'node:test';

import {
  chunkBytes,
  reconstructManifest,
} from '../core/chunking-manifest/js/src/index.mjs';
import {
  loadSelectionAuthority,
  materialize,
} from './chunking-selection-benchmark-common.mjs';

const FIXTURE_BYTES_MAXIMUM = 32 * 1024 * 1024;

function shuffledSource(generated, mutation = null) {
  const rows = generated.chunks.map((part, index) => [
    part.objectId,
    Buffer.from(generated.chunkBytes[index]),
  ]).reverse();
  const source = new Map(rows);
  if (mutation !== null) {
    const bytes = source.get(mutation.objectId);
    assert.ok(bytes, `${mutation.label}: selected object must exist`);
    if (mutation.kind === 'truncate') source.set(mutation.objectId, bytes.subarray(0, bytes.length - 1));
    else bytes[mutation.offset] ^= 1;
  }
  return source;
}

function selectedOccurrences(chunks) {
  const counts = new Map();
  for (const { objectId } of chunks) counts.set(objectId, (counts.get(objectId) ?? 0) + 1);
  const targets = [
    [0, 'early', 'corrupt'],
    [Math.floor((chunks.length - 1) / 2), 'middle', 'corrupt'],
    [chunks.length - 1, 'late', 'truncate'],
  ];
  return targets.map(([target, label, kind]) => {
    const unique = chunks
      .map(({ objectId }, index) => ({ index, objectId }))
      .filter(({ objectId }) => counts.get(objectId) === 1)
      .sort((left, right) => Math.abs(left.index - target) - Math.abs(right.index - target))[0];
    const index = unique?.index ?? target;
    const length = chunks[index].length;
    return {
      kind,
      label,
      objectId: chunks[index].objectId,
      offset: kind === 'corrupt' ? (label === 'middle' ? Math.floor(length / 2) : 0) : null,
    };
  });
}

function publicationRecorder() {
  const state = { aborts: 0, commits: 0, staged: [] };
  return {
    publication: {
      write(fragment) { state.staged.push(Buffer.from(fragment)); },
      commit() { state.commits += 1; return Object.freeze({ committed: true }); },
      abort() { state.aborts += 1; state.staged.length = 0; },
    },
    state,
  };
}

test('all seven bounded workloads reconstruct from shuffled sources and reject representative early, middle, and late damage atomically', { timeout: 180_000 }, async () => {
  const { workloadFile } = await loadSelectionAuthority();
  assert.equal(workloadFile.workloads.length, 7);

  for (const definition of workloadFile.workloads) {
    const candidate = materialize(definition.candidateRecipe);
    assert.ok(candidate.length > 0, definition.workloadId);
    assert.ok(candidate.length <= FIXTURE_BYTES_MAXIMUM, definition.workloadId);
    const generated = await chunkBytes(candidate);
    assert.ok(generated.chunks.length >= 1, definition.workloadId);

    const success = publicationRecorder();
    const reconstructed = await reconstructManifest({
      manifest: generated.manifest.bytes,
      publication: success.publication,
      source: shuffledSource(generated),
    });
    assert.equal(Buffer.concat(success.state.staged).equals(candidate), true, definition.workloadId);
    assert.equal(reconstructed.logicalBytes, String(candidate.length), definition.workloadId);
    assert.deepEqual(
      { aborts: success.state.aborts, commits: success.state.commits },
      { aborts: 0, commits: 1 },
      definition.workloadId,
    );

    for (const mutation of selectedOccurrences(generated.chunks)) {
      const failure = publicationRecorder();
      await assert.rejects(
        reconstructManifest({
          manifest: generated.manifest.bytes,
          publication: failure.publication,
          source: shuffledSource(generated, mutation),
        }),
        (error) => ['CHUNK_DIGEST_MISMATCH', 'CHUNK_SOURCE_TOO_SHORT'].includes(error.code),
        `${definition.workloadId}:${mutation.label}`,
      );
      assert.deepEqual(
        { aborts: failure.state.aborts, commits: failure.state.commits, staged: failure.state.staged.length },
        { aborts: 1, commits: 0, staged: 0 },
        `${definition.workloadId}:${mutation.label}`,
      );
    }
  }
});
