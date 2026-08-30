import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import {
  ERROR_CODES, PROFILE, chunkBytes, chunkIdentity, compareManifest, contentManifest,
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
  const workflow = await (await import('node:fs/promises')).readFile(
    resolve(import.meta.dirname, '../../../../.github/workflows/chunking-manifest-bounded.yml'),
    'utf8',
  );
  assert.match(workflow, /^  javascript:\n/m);
  assert.match(workflow, /^  rust:\n/m);
  assert.match(workflow, /node-version: 24/);
  assert.doesNotMatch(workflow, /(?:100\s*GiB|1\s*TiB|exact-scale)/i);
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
