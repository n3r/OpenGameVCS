#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import {
  CACHE_KEY_DOMAIN, CACHE_KEY_VERSION, ERROR_CODES, GEAR_TABLE_SHA256, LIMITS,
  PROFILE, chunkBytes, chunkCacheKey, createChunker, verifyManifest,
} from '../src/index.mjs';

const output = process.argv[2];
if (!output) throw new Error('usage: bounded-report.mjs <output.json>');
const contract = resolve(import.meta.dirname, '../../../../spec/chunking-manifest/v1');
const golden = JSON.parse(await readFile(resolve(contract, 'vectors/golden.json')));

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

const cases = [];
for (const vector of golden.cases) {
  const bytes = materialize(vector.recipe);
  const generated = await chunkBytes(bytes);
  const source = new Map(generated.chunks.map((part, index) => [part.objectId, generated.chunkBytes[index]]));
  const verified = await verifyManifest({ manifest: generated.manifest.bytes, source });
  cases.push({
    boundaries: generated.boundaries,
    caseId: vector.caseId,
    class: generated.class,
    chunks: generated.chunks.map((part) => ({
      cacheKey: chunkCacheKey(part),
      length: part.length,
      objectId: part.objectId,
    })),
    logicalLength: generated.logicalLength,
    manifestHex: generated.manifest.bytes.toString('hex'),
    manifestObjectId: generated.manifest.objectId,
    partCount: verified.partCount,
    providerReads: verified.providerReads,
    repeatedBytes: verified.repeatedBytes,
    uniqueBytes: verified.uniqueBytes,
    wholeFileSha256: generated.wholeFileDigest.toString('hex'),
  });
}
function errorCode(operation) {
  try { operation(); return null; } catch (error) { return error.code; }
}
const cancellation = new AbortController(); cancellation.abort();
const resourceOutcomes = {
  belowScalarMinimum: errorCode(() => createChunker({
    declaredLength: 0,
    maxWorkingMemoryBytes: LIMITS.scalarWorkingMinimum - 1,
  })),
  cancellation: errorCode(() => createChunker({ declaredLength: 0, signal: cancellation.signal })),
  unsupportedParallelism: errorCode(() => createChunker({ declaredLength: 0, workerCount: 2 })),
};
const report = {
  cacheKey: { domain: CACHE_KEY_DOMAIN, version: CACHE_KEY_VERSION },
  cases,
  errorCodes: ERROR_CODES,
  limits: {
    chunkCountMaximum: LIMITS.chunkCountMaximum,
    logicalMaximum: LIMITS.logicalMaximum,
    maximum: LIMITS.maximum,
    minimum: LIMITS.minimum,
    scalarWorkingMinimum: LIMITS.scalarWorkingMinimum,
    smallMaximum: LIMITS.smallMaximum,
    target: LIMITS.target,
    workingMaximum: LIMITS.workingMaximum,
  },
  profile: `${PROFILE.namespace}/${PROFILE.id}@${PROFILE.major}`,
  resourceOutcomes,
  schemaVersion: 'ogvcs.chunking/bounded-conformance-report/v1',
  tableSha256: GEAR_TABLE_SHA256,
};
await mkdir(dirname(resolve(output)), { recursive: true });
await writeFile(resolve(output), `${JSON.stringify(report, null, 2)}\n`);
