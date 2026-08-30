import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import test from 'node:test';
import { hashObject } from '@opengamevcs/object-model';
import { GEAR_TABLE_SHA256, PROFILE, chunkBytes, createChunker, gearStepU32 } from '../src/index.mjs';

const CONTRACT = resolve(import.meta.dirname, '../../../../spec/chunking-manifest/v1');
const golden = JSON.parse(await readFile(resolve(CONTRACT, 'vectors/golden.json')));
const fragmentation = JSON.parse(await readFile(resolve(CONTRACT, 'vectors/fragmentation.json')));

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
    const base = materialize(recipe.base); return Buffer.concat([base.subarray(0, recipe.offset), Buffer.from(recipe.hex, 'hex'), base.subarray(recipe.offset)]);
  }
  throw new Error(`unknown recipe ${recipe.kind}`);
}

function projection(result) {
  return {
    boundaries: result.boundaries,
    chunks: result.chunks.map(({ length, objectId }) => ({ length, objectId })),
    class: result.class,
    logicalLength: result.logicalLength,
    manifestHex: result.manifest.bytes.toString('hex'),
    manifestObjectId: result.manifest.objectId,
    wholeFileSha256: result.wholeFileDigest.toString('hex'),
  };
}

test('public object-model-backed scalar implementation matches every independent golden vector', async () => {
  assert.equal(GEAR_TABLE_SHA256, golden.tableSha256);
  for (const vector of golden.cases) {
    const bytes = materialize(vector.recipe);
    const result = await chunkBytes(bytes);
    assert.deepEqual(projection(result), vector.expected, vector.caseId);
    for (let index = 0; index < result.chunkBytes.length; index += 1) {
      assert.equal(hashObject(1, result.chunkBytes[index]).toString(), vector.expected.chunks[index].objectId, `${vector.caseId} chunk ${index}`);
    }
    assert.equal(hashObject(2, result.manifest.bytes).toString(), vector.expected.manifestObjectId, `${vector.caseId} manifest`);
  }
});

test('u32-half Gear recurrence is differentially identical to the BigInt oracle', () => {
  const oracleGear = Array.from({ length: 256 }, (_, index) => {
    const suffix = Buffer.alloc(2); suffix.writeUInt16BE(index);
    return createHash('sha256').update('OpenGameVCS Gear table v1\0').update(suffix).digest().readBigUInt64BE(0);
  });
  let high = 0; let low = 0; let oracle = 0n; let random = 0x7f4a7c15;
  for (let index = 0; index < 200_000; index += 1) {
    random = (Math.imul(random, 1664525) + 1013904223) >>> 0;
    const byte = random & 0xff;
    const next = gearStepU32(high, low, byte); high = next.high; low = next.low;
    oracle = ((oracle << 1n) + oracleGear[byte]) & 0xffff_ffff_ffff_ffffn;
    assert.equal((BigInt(high) << 32n) | BigInt(low), oracle, `step ${index}`);
  }
});

test('fragment boundaries and public manifest identity do not depend on update fragmentation', async () => {
  for (const fixture of fragmentation.cases) {
    const vector = golden.cases.find(({ caseId }) => caseId === fixture.caseId);
    const bytes = materialize(vector.recipe);
    for (const pattern of fixture.fragmentPatterns) {
      const chunks = []; const session = createChunker({ declaredLength: bytes.length, onChunk: (chunk) => chunks.push(Buffer.from(chunk)) });
      let offset = 0; let cursor = 0;
      while (offset < bytes.length) {
        const take = Math.min(pattern[cursor % pattern.length], bytes.length - offset);
        session.update(bytes.subarray(offset, offset + take)); offset += take; cursor += 1;
      }
      const result = await session.finish();
      assert.deepEqual(projection(result), vector.expected, `${fixture.caseId} pattern ${pattern}`);
      assert.equal(Buffer.concat(chunks).equals(bytes), true);
    }
  }
});

test('unsupported profile, length mismatches, and sink failure poison the session', async () => {
  assert.throws(() => createChunker({ declaredLength: 0, profile: { ...PROFILE, major: 2 } }), { code: 'CHUNK_PROFILE_UNSUPPORTED' });
  assert.throws(() => createChunker({ declaredLength: 0, maxWorkingMemoryBytes: 2_097_151 }), { code: 'CHUNK_RESOURCE_EXHAUSTED' });
  assert.throws(() => createChunker({ declaredLength: 0, workerCount: 2 }), { code: 'CHUNK_RESOURCE_UNSUPPORTED' });
  const oversizedFragment = createChunker({ declaredLength: 67_108_865 });
  assert.throws(() => oversizedFragment.update(Buffer.allocUnsafe(67_108_865)), { code: 'CHUNK_FRAGMENT_INVALID' });
  assert.throws(() => oversizedFragment.update(Buffer.alloc(0)), { code: 'CHUNK_SESSION_FAILED' });
  const short = createChunker({ declaredLength: 2 }); short.update(Buffer.from([1]));
  await assert.rejects(short.finish(), { code: 'CHUNK_SOURCE_TOO_SHORT' });
  assert.throws(() => short.update(Buffer.alloc(0)), { code: 'CHUNK_SESSION_FAILED' });

  let deliveries = 0;
  const sinkFailure = createChunker({ declaredLength: 262144, onChunk() { deliveries += 1; throw new Error('sink failed'); } });
  sinkFailure.update(Buffer.alloc(262144));
  await assert.rejects(sinkFailure.finish(), { code: 'CHUNK_SINK_FAILED' });
  assert.equal(deliveries, 1);
  assert.throws(() => sinkFailure.update(Buffer.alloc(0)), { code: 'CHUNK_SESSION_FAILED' });
  await assert.rejects(sinkFailure.finish(), { code: 'CHUNK_SESSION_FAILED' });
  assert.equal(deliveries, 1);
});
