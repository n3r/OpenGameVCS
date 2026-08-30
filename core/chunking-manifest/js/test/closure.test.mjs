import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import {
  openWorkspaceRoot, preflightWorkspaceMaterialization, probeFilesystemCapabilities,
} from '@opengamevcs/path-filesystem';
import {
  ChunkingError, ERROR_CODES, PROFILE, VERIFICATION_RECEIPT_VERIFIER, chunkBytes, chunkCacheKey, chunkIdentity,
  compareManifest, consumeVerificationReceipt, contentManifest, createAtomicWriteStreamPublicationAdapter,
  createChunker, reconstructManifest, verifyManifest,
} from '../src/index.mjs';

const CONTRACT = resolve(import.meta.dirname, '../../../../spec/chunking-manifest/v1');
const golden = JSON.parse(await (await import('node:fs/promises')).readFile(resolve(CONTRACT, 'vectors/golden.json')));
const malformed = JSON.parse(await (await import('node:fs/promises')).readFile(resolve(CONTRACT, 'vectors/malformed.json')));
const errorRegistry = JSON.parse(await (await import('node:fs/promises')).readFile(resolve(CONTRACT, 'registries/errors.json')));

function materialize(recipe) {
  if (recipe.kind === 'literal') return Buffer.from(recipe.hex, 'hex');
  if (recipe.kind === 'repeat') return Buffer.alloc(recipe.length, recipe.byte);
  if (recipe.kind === 'sha256-counter') {
    const result = Buffer.alloc(recipe.length); let offset = 0; let counter = 0n;
    while (offset < result.length) {
      const suffix = Buffer.alloc(8); suffix.writeBigUInt64BE(counter);
      const block = createHash('sha256').update('OpenGameVCS chunk vector block v1\0').update(recipe.seed).update('\0').update(suffix).digest();
      const take = Math.min(32, result.length - offset); block.copy(result, offset, 0, take); offset += take; counter += 1n;
    }
    return result;
  }
  if (recipe.kind === 'insert') {
    const base = materialize(recipe.base);
    return Buffer.concat([base.subarray(0, recipe.offset), Buffer.from(recipe.hex, 'hex'), base.subarray(recipe.offset)]);
  }
  throw new Error(`unknown recipe ${recipe.kind}`);
}

function sourceMap(result, transform = (bytes) => bytes) {
  return new Map(result.chunks.map((part, index) => [part.objectId, transform(Buffer.from(result.chunkBytes[index]), index)]).reverse());
}

async function prepared(caseId = 'counter-a-six-mib') {
  const vector = golden.cases.find((item) => item.caseId === caseId);
  const bytes = materialize(vector.recipe);
  const result = await chunkBytes(bytes);
  return { bytes, result, source: sourceMap(result), vector };
}

async function shiftedBoundaryFixture() {
  const fixture = await prepared();
  assert.ok(fixture.result.boundaries.length > 1);
  const boundaries = [...fixture.result.boundaries];
  boundaries[0] += 1;
  const parts = [];
  const source = new Map();
  let offset = 0;
  for (const boundary of boundaries) {
    const bytes = fixture.bytes.subarray(offset, boundary);
    const identity = chunkIdentity(bytes);
    parts.push({ ...identity, length: bytes.length });
    source.set(identity.objectId, Buffer.from(bytes));
    offset = boundary;
  }
  const manifest = await contentManifest(
    fixture.bytes.length,
    createHash('sha256').update(fixture.bytes).digest(),
    parts,
  );
  return { manifest, source };
}

async function publicationPlan(workspace, path) {
  const capabilities = await probeFilesystemCapabilities(workspace.root);
  const segments = path.split('/');
  const entries = [];
  for (let index = 1; index < segments.length; index += 1) {
    entries.push({
      id: `parent-${index}`,
      path: segments.slice(0, index).join('/'),
      kind: 'directory',
      mode: 'directory',
    });
  }
  entries.push({ id: 'asset', path, kind: 'regular', mode: 'regular-file' });
  return preflightWorkspaceMaterialization(workspace, {
    schemaVersion: 'ogvcs.path/preflight-request/v1',
    caseMode: workspace.caseMode,
    profile: workspace.profile,
    platform: capabilities.platform,
    capabilities: {
      atomicReplace: capabilities.atomicReplace,
      executableBit: capabilities.executableBit,
      symlink: capabilities.symlink,
    },
    entries,
  });
}

test('generated shared registry exactly matches the public JavaScript error surface', () => {
  assert.deepEqual(errorRegistry.entries.map(({ name }) => name), ERROR_CODES);
});

test('static Rust stable-code mapping has exact generated-registry parity', async () => {
  const rust = await (await import('node:fs/promises')).readFile(
    resolve(import.meta.dirname, '../../rust/src/lib.rs'),
    'utf8',
  );
  const mapped = [...rust.matchAll(/=> "(CHUNK_[A-Z_]+)"/g)].map((match) => match[1]);
  assert.deepEqual(mapped, ERROR_CODES);
});

test('bounded workflow keeps languages parallel and excludes scale campaigns', async () => {
  const { readFile } = await import('node:fs/promises');
  const [workflow, packedConsumer] = await Promise.all([
    readFile(
      resolve(import.meta.dirname, '../../../../.github/workflows/chunking-manifest-bounded.yml'),
      'utf8',
    ),
    readFile(resolve(import.meta.dirname, '../scripts/packed-offline.mjs'), 'utf8'),
  ]);
  assert.match(workflow, /^  javascript:\n/m);
  assert.match(workflow, /^  rust:\n/m);
  assert.match(workflow, /node-version: 24/);
  assert.match(workflow, /cargo fmt .* --check/);
  assert.match(workflow, /cargo test .* --locked/);
  assert.match(workflow, /cargo package .* --offline/);
  assert.match(workflow, /npm run test:packed/);
  assert.doesNotMatch(workflow, /(?:100\s*GiB|1\s*TiB|exact-scale)/i);
  assert.match(packedConsumer, /process\.env\.npm_execpath/);
  assert.match(packedConsumer, /process\.platform === 'win32'/);
});

test('every golden manifest verifies and shuffled lookup order does not affect reconstruction', async () => {
  for (const vector of golden.cases) {
    const bytes = materialize(vector.recipe);
    const generated = await chunkBytes(bytes);
    const source = sourceMap(generated);
    const verified = await verifyManifest({
      manifest: generated.manifest.bytes,
      expectedManifestObjectId: generated.manifest.objectId,
      source,
    });
    assert.equal(verified.logicalBytes, String(bytes.length), vector.caseId);
    assert.equal(verified.partCount, generated.chunks.length, vector.caseId);

    const staged = [];
    let commits = 0; let aborts = 0;
    const reconstructed = await reconstructManifest({
      manifest: generated.manifest.bytes,
      source,
      publication: {
        write(fragment) { staged.push(Buffer.from(fragment)); },
        commit() { commits += 1; return { bytes: staged.reduce((sum, part) => sum + part.length, 0) }; },
        abort() { aborts += 1; staged.length = 0; },
      },
    });
    assert.equal(Buffer.concat(staged).equals(bytes), true, vector.caseId);
    assert.equal(reconstructed.logicalBytes, String(bytes.length));
    assert.equal(commits, 1); assert.equal(aborts, 0);
  }
});

test('deterministic property inputs survive arbitrary source fragmentation and exact reconstruction', async () => {
  let state = 0x73a4f29d;
  for (const length of [0, 1, 31, 262_143, 262_144, 262_145, 524_289, 1_048_577, 2_097_153, 2_500_003]) {
    const bytes = Buffer.allocUnsafe(length);
    for (let index = 0; index < bytes.length; index += 1) {
      state = (Math.imul(state, 1_664_525) + 1_013_904_223) >>> 0;
      bytes[index] = state >>> 24;
    }
    const generated = await chunkBytes(bytes);
    const fragmented = new Map(generated.chunks.map((part, index) => {
      const chunk = generated.chunkBytes[index];
      const pieces = [];
      for (let offset = 0, width = 1; offset < chunk.length; width = (width * 17) % 4096 + 1) {
        pieces.push(chunk.subarray(offset, Math.min(offset + width, chunk.length)));
        offset += width;
      }
      return [part.objectId, pieces];
    }));
    const output = [];
    await reconstructManifest({
      manifest: generated.manifest.bytes,
      source: fragmented,
      publication: {
        write(part) { output.push(Buffer.from(part)); },
        commit() {},
        abort() { output.length = 0; },
      },
    });
    assert.equal(Buffer.concat(output).equals(bytes), true, `length ${length}`);
  }
});

test('repeated references are read per occurrence and compare accounting is exact', async () => {
  const fixture = await prepared('zero-five-mib');
  assert.ok(new Set(fixture.result.chunks.map(({ objectId }) => objectId)).size < fixture.result.chunks.length);
  const verified = await verifyManifest({ manifest: fixture.result.manifest.bytes, source: fixture.source });
  assert.equal(verified.providerReads, fixture.result.chunks.length);
  const repeated = fixture.result.chunks.reduce((total, part, index, all) =>
    total + (all.findIndex((candidate) => candidate.objectId === part.objectId) === index ? 0 : part.length), 0);
  assert.equal(verified.repeatedBytes, String(repeated));

  const known = new Map([[fixture.result.chunks[0].objectId, fixture.result.chunks[0].length]]);
  const comparison = await compareManifest({ manifest: fixture.result.manifest.bytes, knownChunks: known });
  assert.equal(comparison.repeatedBytes, String(repeated));
  assert.equal(comparison.reusedBytes, String(fixture.result.chunks[0].length));
  assert.equal(BigInt(comparison.uniqueBytes), BigInt(comparison.reusedBytes) + BigInt(comparison.newlyRequiredBytes));
});

test('conflicting metadata and conflicting known-index lengths fail deterministically', async () => {
  const bytes = Buffer.from([1]);
  const identity = chunkIdentity(bytes);
  const conflicting = await contentManifest(3, createHash('sha256').update(Buffer.from([1, 1, 1])).digest(), [
    { ...identity, length: 1 }, { ...identity, length: 2 },
  ]);
  await assert.rejects(compareManifest({ manifest: conflicting.bytes }), { code: 'CHUNK_METADATA_CONFLICT' });

  const fixture = await prepared('tiny-ascii');
  await assert.rejects(compareManifest({
    manifest: fixture.result.manifest.bytes,
    knownChunks: new Map([[fixture.result.chunks[0].objectId, fixture.result.chunks[0].length + 1]]),
  }), { code: 'CHUNK_METADATA_CONFLICT' });
  await assert.rejects(compareManifest({
    manifest: fixture.result.manifest.bytes,
    maxIndexMemoryBytes: 0,
  }), { code: 'CHUNK_RESOURCE_EXHAUSTED' });
});

test('mutation failures abort staged reconstruction and never commit', async () => {
  const fixture = await prepared();
  const corrupted = sourceMap(fixture.result, (bytes, index) => {
    if (index === 0) bytes[0] ^= 1;
    return bytes;
  });
  const staged = [];
  let commits = 0; let aborts = 0;
  await assert.rejects(reconstructManifest({
    manifest: fixture.result.manifest.bytes,
    source: corrupted,
    publication: {
      write(part) { staged.push(Buffer.from(part)); },
      commit() { commits += 1; },
      abort() { aborts += 1; staged.length = 0; },
    },
  }), { code: 'CHUNK_DIGEST_MISMATCH' });
  assert.equal(commits, 0); assert.equal(aborts, 1); assert.deepEqual(staged, []);
});

test('pre-write and empty commit failures abort exactly once without publication', async () => {
  const fixture = await prepared('tiny-ascii');
  let writes = 0; let commits = 0; let aborts = 0;
  const publication = {
    write() { writes += 1; },
    commit() { commits += 1; },
    abort() { aborts += 1; },
  };
  await assert.rejects(reconstructManifest({
    manifest: fixture.result.manifest.bytes,
    source: new Map(),
    publication,
  }), { code: 'CHUNK_SOURCE_MISSING' });
  assert.deepEqual({ writes, commits, aborts }, { writes: 0, commits: 0, aborts: 1 });

  const empty = await chunkBytes(Buffer.alloc(0));
  writes = 0; commits = 0; aborts = 0;
  await assert.rejects(reconstructManifest({
    manifest: empty.manifest.bytes,
    source: new Map(),
    publication: {
      write() { writes += 1; },
      commit() { commits += 1; throw new Error('commit failed'); },
      abort() { aborts += 1; throw new Error('abort failed after cleanup'); },
    },
  }), (error) => error instanceof ChunkingError && error.code === 'CHUNK_PUBLICATION_FAILED');
  assert.deepEqual({ writes, commits, aborts }, { writes: 0, commits: 1, aborts: 1 });
});

test('external throws and iterator failures use only the generated error authority', async () => {
  const fixture = await prepared('tiny-ascii');
  const expectExact = async (operation, code) => assert.rejects(operation, (error) => {
    assert.equal(error instanceof ChunkingError, true);
    assert.equal(ERROR_CODES.includes(error.code), true);
    return error.code === code;
  });

  await expectExact(() => verifyManifest({
    manifest: fixture.result.manifest.bytes,
    source() { throw Object.assign(new Error('provider'), { code: 'CHUNK_NOT_AUTHORIZED' }); },
  }), 'CHUNK_SOURCE_INVALID');

  let returned = 0; let aborts = 0; let commits = 0;
  await expectExact(() => reconstructManifest({
    manifest: fixture.result.manifest.bytes,
    source() {
      return {
        [Symbol.asyncIterator]() {
          return {
            next() { throw new Error('iterator next'); },
            return() { returned += 1; throw new Error('iterator return'); },
          };
        },
      };
    },
    publication: {
      write() { throw new Error('must not write'); },
      commit() { commits += 1; },
      abort() { aborts += 1; },
    },
  }), 'CHUNK_SOURCE_INVALID');
  assert.deepEqual({ returned, commits, aborts }, { returned: 1, commits: 0, aborts: 1 });

  await expectExact(() => compareManifest({
    manifest: fixture.result.manifest.bytes,
    knownChunks() { throw new RangeError('known index'); },
  }), 'CHUNK_SOURCE_INVALID');
});

test('default result compatibility, cancellation/deadline, and cache keys are stable', async () => {
  const bytes = Buffer.from('compatibility');
  const chunks = [];
  const session = createChunker({ declaredLength: bytes.length, onChunk: (chunk) => chunks.push(Buffer.from(chunk)) });
  session.update(bytes);
  const generated = await session.finish();
  assert.deepEqual(generated.boundaries, [bytes.length]);
  assert.equal(generated.chunks.length, 1);

  const expected = createHash('sha256')
    .update('OpenGameVCS chunk cache key v1\0', 'ascii')
    .update('chunking.opengamevcs/gear-fastcdc-1m@1', 'ascii')
    .update('\0', 'ascii')
    .update(generated.chunks[0].objectId, 'ascii')
    .digest('hex');
  assert.equal(chunkCacheKey(generated.chunks[0]), `ogvcs:chunk-cache:v1:sha256:${expected}`);

  const cancellation = new AbortController();
  cancellation.abort();
  assert.throws(() => createChunker({
    declaredLength: 0,
    signal: cancellation.signal,
  }), { code: 'CHUNK_RESOURCE_EXHAUSTED' });
  await assert.rejects(verifyManifest({
    manifest: generated.manifest.bytes,
    source: new Map([[generated.chunks[0].objectId, bytes]]),
    maxElapsedMilliseconds: 0,
  }), { code: 'CHUNK_RESOURCE_EXHAUSTED' });

  const midFlight = new AbortController();
  let commits = 0; let aborts = 0;
  await assert.rejects(reconstructManifest({
    manifest: generated.manifest.bytes,
    signal: midFlight.signal,
    source() { midFlight.abort(); return bytes; },
    publication: {
      write() { throw new Error('cancelled bytes must not publish'); },
      commit() { commits += 1; },
      abort() { aborts += 1; },
    },
  }), { code: 'CHUNK_RESOURCE_EXHAUSTED' });
  assert.deepEqual({ commits, aborts }, { commits: 0, aborts: 1 });
});

test('atomic write adapter binds a one-use verification receipt to workspace publication', async () => {
  const fixture = await prepared('tiny-ascii');
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-chunk-publication-'));
  try {
    const workspace = await openWorkspaceRoot(root);
    const plan = await publicationPlan(workspace, 'Content/asset.bin');
    const reconstructed = await reconstructManifest({
      manifest: fixture.result.manifest.bytes,
      source: fixture.source,
      publication: createAtomicWriteStreamPublicationAdapter(workspace, 'Content/asset.bin', {
        manifest: fixture.result.manifest.bytes,
        createParents: true,
        plan,
        maxBytes: fixture.bytes.length,
        maxScratchBytes: fixture.bytes.length,
      }),
    });
    const published = reconstructed.publicationResult.workspacePublication;
    assert.equal(Buffer.compare(await readFile(join(root, 'Content', 'asset.bin')), fixture.bytes), 0);
    assert.equal(published.path, 'Content/asset.bin');
    assert.equal(published.bytes, fixture.bytes.length);
    assert.equal(published.sha256, createHash('sha256').update(fixture.bytes).digest('hex'));
    const receipt = consumeVerificationReceipt(reconstructed.verificationReceipt, {
      verifier: VERIFICATION_RECEIPT_VERIFIER,
      profile: `${PROFILE.namespace}/${PROFILE.id}@${PROFILE.major}`,
      manifest: fixture.result.manifest.bytes,
      manifestObjectId: fixture.result.manifest.objectId,
      logicalBytes: String(fixture.bytes.length),
      wholeFileSha256: published.sha256,
      workspacePublication: published,
    });
    assert.equal(receipt.workspacePublication.transaction, published.transaction);
    assert.throws(() => consumeVerificationReceipt(reconstructed.verificationReceipt), { code: 'CHUNK_RESOURCE_INVALID' });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('hostile publication receipts fail closed before trusted publication', async () => {
  const fixture = await prepared('tiny-ascii');
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-chunk-hostile-publication-'));
  try {
    const workspace = await openWorkspaceRoot(root);
    const plan = await publicationPlan(workspace, 'Content/asset.bin');
    const publication = createAtomicWriteStreamPublicationAdapter(workspace, 'Content/asset.bin', {
      manifest: fixture.result.manifest.bytes,
      createParents: true,
      plan,
      maxBytes: fixture.bytes.length,
      maxScratchBytes: fixture.bytes.length,
    });
    publication.write(fixture.bytes);
    await assert.rejects(
      publication.commit({ verificationReceipt: Object.freeze({ verifier: VERIFICATION_RECEIPT_VERIFIER }) }),
      { code: 'CHUNK_PUBLICATION_FAILED' },
    );
    await assert.rejects(readFile(join(root, 'Content', 'asset.bin')), { code: 'ENOENT' });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('OGVCS-002 structure and content errors precede deferred Gear mismatch', async () => {
  const fixture = await prepared();
  let reads = 0;
  const invalidManifest = Buffer.from(fixture.result.manifest.bytes);
  invalidManifest[0] ^= 1;
  await assert.rejects(verifyManifest({
    manifest: invalidManifest,
    source() { reads += 1; return Buffer.alloc(0); },
  }), { code: 'CHUNK_MANIFEST_MISMATCH' });
  assert.equal(reads, 0);

  const shifted = await shiftedBoundaryFixture();
  const [firstId, firstBytes] = shifted.source.entries().next().value;
  const corrupted = new Map(shifted.source);
  const changed = Buffer.from(firstBytes); changed[0] ^= 1; corrupted.set(firstId, changed);
  await assert.rejects(verifyManifest({ manifest: shifted.manifest.bytes, source: corrupted }), {
    code: 'CHUNK_DIGEST_MISMATCH',
  });
});

test('missing, short, long, and first/middle/last corrupt deliveries fail closed', async () => {
  const fixture = await prepared();
  const first = fixture.result.chunks[0];
  const original = fixture.source.get(first.objectId);

  const missing = new Map(fixture.source); missing.delete(first.objectId);
  await assert.rejects(verifyManifest({ manifest: fixture.result.manifest.bytes, source: missing }), {
    code: 'CHUNK_SOURCE_MISSING',
  });

  const short = new Map(fixture.source); short.set(first.objectId, original.subarray(0, original.length - 1));
  await assert.rejects(verifyManifest({ manifest: fixture.result.manifest.bytes, source: short }), {
    code: 'CHUNK_DIGEST_MISMATCH',
  });

  const long = new Map(fixture.source); long.set(first.objectId, Buffer.concat([original, Buffer.of(0)]));
  await assert.rejects(verifyManifest({ manifest: fixture.result.manifest.bytes, source: long }), {
    code: 'CHUNK_DIGEST_MISMATCH',
  });

  for (const position of [0, Math.floor(original.length / 2), original.length - 1]) {
    const source = new Map(fixture.source);
    const changed = Buffer.from(original); changed[position] ^= 0x80; source.set(first.objectId, changed);
    await assert.rejects(verifyManifest({ manifest: fixture.result.manifest.bytes, source }), {
      code: 'CHUNK_DIGEST_MISMATCH',
    });
  }
});

test('scratch spill and exhaustion are bounded and leave no artifacts', async () => {
  const scratch = await mkdtemp(join(tmpdir(), 'ogvcs-chunk-test-'));
  try {
    const fixture = await prepared();
    const generated = await chunkBytes(fixture.bytes, {
      maxLedgerMemoryBytes: 0,
      maxScratchBytes: 1024 * 1024,
      scratchDirectory: scratch,
    });
    assert.equal(generated.ledger.spilled, true);
    assert.deepEqual(await readdir(scratch), []);

    const verified = await verifyManifest({
      manifest: generated.manifest.bytes,
      source: sourceMap(generated),
      maxLedgerMemoryBytes: 0,
      maxScratchBytes: 1024 * 1024,
      scratchDirectory: scratch,
    });
    assert.equal(verified.ledger.spilled, true);
    assert.deepEqual(await readdir(scratch), []);

    const abandoned = createChunker({
      declaredLength: 2_097_152,
      maxLedgerMemoryBytes: 0,
      maxScratchBytes: 1024 * 1024,
      scratchDirectory: scratch,
    });
    abandoned.update(Buffer.alloc(2_097_152));
    assert.notDeepEqual(await readdir(scratch), []);
    assert.equal(abandoned.abort(), true);
    assert.deepEqual(await readdir(scratch), []);

    const identity = chunkIdentity(Buffer.of(1));
    const conflicting = await contentManifest(3, createHash('sha256').update(Buffer.of(1, 1, 1)).digest(), [
      { ...identity, length: 1 }, { ...identity, length: 2 },
    ]);
    await assert.rejects(compareManifest({
      manifest: conflicting.bytes,
      maxLedgerMemoryBytes: 0,
      maxScratchBytes: 1024 * 1024,
      scratchDirectory: scratch,
    }), { code: 'CHUNK_METADATA_CONFLICT' });
    assert.deepEqual(await readdir(scratch), []);

    const session = createChunker({
      declaredLength: 2_097_152,
      maxLedgerMemoryBytes: 0,
      maxScratchBytes: 0,
      scratchDirectory: scratch,
    });
    assert.throws(() => session.update(Buffer.alloc(2_097_152)), { code: 'CHUNK_SCRATCH_EXHAUSTED' });
    assert.deepEqual(await readdir(scratch), []);
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
});

test('every malformed vector is executed by its declared operation', async () => {
  const fixture = await prepared();
  const executed = [];
  for (const vector of malformed.cases) {
    const { parameters } = vector;
    let operation;
    if (vector.operation === 'chunk') {
      operation = async () => {
        let profile = PROFILE;
        if (parameters.profile) {
          const match = /^([^/]+)\/([^@]+)@(\d+)$/.exec(parameters.profile);
          profile = { namespace: match[1], id: match[2], major: Number(match[3]) };
        }
        const session = createChunker({
          declaredLength: parameters.declaredLength,
          profile,
          maxWorkingMemoryBytes: parameters.maxWorkingMemoryBytes,
        });
        if (parameters.fragmentLength !== undefined) session.update(Buffer.alloc(parameters.fragmentLength));
        else if (parameters.sourceHex !== undefined) session.update(Buffer.from(parameters.sourceHex, 'hex'));
        await session.finish();
      };
    } else if (vector.caseId === 'boundary-shift') {
      operation = async () => {
        const shifted = await shiftedBoundaryFixture();
        await verifyManifest({ manifest: shifted.manifest.bytes, source: shifted.source });
      };
    } else if (vector.caseId === 'chunk-bit-flip') {
      operation = () => verifyManifest({
        manifest: fixture.result.manifest.bytes,
        source: sourceMap(fixture.result, (bytes, index) => {
          if (index === parameters.chunkIndex) bytes[0] ^= parameters.xor;
          return bytes;
        }),
      });
    } else if (vector.caseId === 'manifest-bit-flip') {
      operation = () => {
        const bytes = Buffer.from(fixture.result.manifest.bytes);
        bytes[parameters.manifestByte] ^= parameters.xor;
        return verifyManifest({ manifest: bytes, source: fixture.source });
      };
    } else throw new Error(`unhandled malformed vector ${vector.caseId}`);
    await assert.rejects(operation, { code: vector.expectedError }, vector.caseId);
    executed.push(vector.caseId);
  }
  assert.deepEqual(executed, malformed.cases.map(({ caseId }) => caseId));
});
