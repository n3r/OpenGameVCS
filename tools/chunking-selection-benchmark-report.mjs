#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { resolve, dirname, join } from 'node:path';
import { gzipSync } from 'node:zlib';
import { fileURLToPath } from 'node:url';

import { chunkBytes, compareManifest, verifyManifest, LIMITS } from '../core/chunking-manifest/js/src/index.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SPEC_ROOT = resolve(ROOT, 'spec/chunking-manifest/v1');
const PACKAGE_JSON = resolve(ROOT, 'core/chunking-manifest/js/package.json');

function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string' || Number.isSafeInteger(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}

function sha256(value) {
  return createHash('sha256').update(typeof value === 'string' || Buffer.isBuffer(value) ? value : canonicalJson(value)).digest('hex');
}

async function json(path) {
  return JSON.parse(await readFile(path, 'utf8'));
}

function parseArguments(argv) {
  if (argv.length !== 2 || argv[0] !== '--output' || argv[1].length === 0) {
    throw new Error('usage: node tools/chunking-selection-benchmark-report.mjs --output <report.json>');
  }
  return resolve(process.cwd(), argv[1]);
}

function sha256Counter(seed, length) {
  const output = Buffer.alloc(length);
  let offset = 0;
  let counter = 0n;
  while (offset < output.length) {
    const suffix = Buffer.alloc(8);
    suffix.writeBigUInt64BE(counter);
    const block = createHash('sha256')
      .update('OpenGameVCS chunk vector block v1\0')
      .update(seed)
      .update('\0')
      .update(suffix)
      .digest();
    const take = Math.min(32, output.length - offset);
    block.copy(output, offset, 0, take);
    offset += take;
    counter += 1n;
  }
  return output;
}

function sourceLikeText({ lines, salt = 0, editStartLine = 0, editLineCount = 0 }) {
  const rows = [];
  for (let index = 0; index < lines; index += 1) {
    const edited = index >= editStartLine && index < editStartLine + editLineCount;
    const value = edited ? (index * (salt + 7)) % 997 : index % 997;
    const flags = edited ? (index + salt) % 19 : index % 19;
    rows.push(`asset_${index.toString(16).padStart(6, '0')} class=${index % 5} value=${value.toString().padStart(3, '0')} flags=${flags.toString().padStart(2, '0')}\n`);
  }
  return Buffer.from(rows.join(''), 'utf8');
}

function structuredRecords({ records, salt = 0, editStartRecord = 0, editRecordCount = 0 }) {
  const rows = [];
  for (let index = 0; index < records; index += 1) {
    const edited = index >= editStartRecord && index < editStartRecord + editRecordCount;
    const weight = edited ? ((index * 31) + salt) % 10000 : index % 10000;
    const enabled = edited ? (index + salt) % 2 : index % 2;
    rows.push(`{"id":"${index.toString().padStart(6, '0')}","zone":"${(index % 32).toString().padStart(2, '0')}","owner":"${(index % 7).toString().padStart(2, '0')}","enabled":"${enabled}","weight":"${weight.toString().padStart(4, '0')}"}\n`);
  }
  return Buffer.from(rows.join(''), 'utf8');
}

function materialize(recipe) {
  switch (recipe.kind) {
    case 'literal':
      return Buffer.from(recipe.hex, 'hex');
    case 'sha256-counter':
      return sha256Counter(recipe.seed, recipe.length);
    case 'source-like-text':
      return sourceLikeText(recipe);
    case 'structured-records':
      return structuredRecords(recipe);
    case 'gzip':
      return gzipSync(materialize(recipe.source), { mtime: 0 });
    case 'insert': {
      const base = materialize(recipe.base);
      return Buffer.concat([base.subarray(0, recipe.offset), Buffer.from(recipe.hex, 'hex'), base.subarray(recipe.offset)]);
    }
    case 'replace-window': {
      const base = materialize(recipe.base);
      const replacement = materialize(recipe.replacement);
      return Buffer.concat([base.subarray(0, recipe.offset), replacement, base.subarray(recipe.offset + replacement.length)]);
    }
    case 'append': {
      const base = materialize(recipe.base);
      return Buffer.concat([base, materialize(recipe.suffix)]);
    }
    default:
      throw new Error(`unknown recipe kind ${recipe.kind}`);
  }
}

function measureMicroseconds(operation) {
  const start = process.hrtime.bigint();
  const value = operation();
  return Promise.resolve(value).then((resolved) => ({
    elapsedMicroseconds: Number((process.hrtime.bigint() - start) / 1000n),
    value: resolved,
  }));
}

function throughputBytesPerSecond(bytes, elapsedMicroseconds) {
  if (!Number.isSafeInteger(bytes) || bytes < 0) throw new Error('throughput bytes must be a non-negative safe integer');
  return elapsedMicroseconds === 0 ? bytes * 1_000_000 : Math.floor((bytes * 1_000_000) / elapsedMicroseconds);
}

function firstDifference(left, right) {
  const maximum = Math.min(left.length, right.length);
  for (let index = 0; index < maximum; index += 1) {
    if (left[index] !== right[index]) return index;
  }
  return maximum;
}

function sharedSuffixBytes(left, right, prefixBytes) {
  let count = 0;
  while (count < left.length - prefixBytes && count < right.length - prefixBytes) {
    if (left[left.length - 1 - count] !== right[right.length - 1 - count]) break;
    count += 1;
  }
  return count;
}

function evaluateThresholds(thresholdFile, workloads) {
  const rows = [];
  const workloadMap = new Map(workloads.map((row) => [row.workloadId, row]));
  const workloadCount = workloads.length;
  const successCount = workloads.filter(({ success }) => success).length;
  const accountingMismatchCount = workloads.filter(({ accounting }) => !accounting.balanced).length;
  for (const entry of thresholdFile.entries) {
    let actual;
    switch (entry.metric) {
      case 'workloadCount':
        actual = workloadCount;
        break;
      case 'successCount':
        actual = entry.workloadId === '*'
          ? successCount
          : workloadMap.get(entry.workloadId)?.success ? 1 : 0;
        break;
      case 'accountingMismatchCount':
        actual = accountingMismatchCount;
        break;
      case 'reusedBytes':
        actual = Number(workloadMap.get(entry.workloadId)?.compare.reusedBytes ?? 0);
        break;
      case 'newlyRequiredBytes':
        actual = Number(workloadMap.get(entry.workloadId)?.compare.newlyRequiredBytes ?? 0);
        break;
      case 'resynchronizationDistanceBytes': {
        const value = workloadMap.get(entry.workloadId)?.deltas.resynchronizationDistanceBytes;
        actual = value === null ? Number.MAX_SAFE_INTEGER : value;
        break;
      }
      default:
        throw new Error(`unknown threshold metric ${entry.metric}`);
    }
    const passed = entry.operator === 'maximum' ? actual <= entry.value : actual >= entry.value;
    rows.push({
      actual,
      expected: entry.value,
      metric: entry.metric,
      operator: entry.operator,
      requirementId: entry.requirementId,
      schemaVersion: 'ogvcs.chunking/selection-benchmark-threshold-evaluation/v1',
      severity: entry.severity,
      status: passed ? 'passed' : 'failed',
      thresholdId: entry.id,
      workloadId: entry.workloadId,
    });
  }
  return rows;
}

export async function buildChunkingSelectionReport() {
  const [contract, thresholdFile, workloadFile, packageJson] = await Promise.all([
    json(join(SPEC_ROOT, 'manifest.json')),
    json(join(SPEC_ROOT, 'thresholds/selection-bounded-v1.json')),
    json(join(SPEC_ROOT, 'vectors/selection-benchmark-workloads.json')),
    json(PACKAGE_JSON),
  ]);
  const workloads = [];
  for (const definition of workloadFile.workloads) {
    const baseBytes = materialize(definition.baseRecipe);
    const candidateBytes = materialize(definition.candidateRecipe);
    const base = await measureMicroseconds(() => chunkBytes(baseBytes));
    const candidate = await measureMicroseconds(() => chunkBytes(candidateBytes));
    const knownChunks = new Map(base.value.chunks.map((part) => [part.objectId, part.length]));
    const comparison = await measureMicroseconds(() => compareManifest({
      manifest: candidate.value.manifest.bytes,
      knownChunks,
    }));
    const source = new Map(candidate.value.chunks.map((part, index) => [part.objectId, candidate.value.chunkBytes[index]]));
    const verification = await measureMicroseconds(() => verifyManifest({
      manifest: candidate.value.manifest.bytes,
      source,
    }));
    const prefixBytes = firstDifference(baseBytes, candidateBytes);
    const suffixBytes = sharedSuffixBytes(baseBytes, candidateBytes, prefixBytes);
    const resynchronizationDistanceBytes = suffixBytes > 0 && prefixBytes < candidateBytes.length
      ? candidateBytes.length - suffixBytes - prefixBytes
      : null;
    const accounting = {
      balanced: Number(comparison.value.reusedBytes) + Number(comparison.value.newlyRequiredBytes) === Number(comparison.value.uniqueBytes)
        && Number(comparison.value.logicalBytes) === Number(comparison.value.uniqueBytes) + Number(comparison.value.repeatedBytes)
        && Number(verification.value.uniqueBytes) === Number(comparison.value.uniqueBytes)
        && Number(verification.value.repeatedBytes) === Number(comparison.value.repeatedBytes),
      schemaVersion: 'ogvcs.chunking/selection-benchmark-accounting/v1',
    };
    workloads.push({
      accounting,
      base: {
        generationMicroseconds: base.elapsedMicroseconds,
        ledger: base.value.ledger,
        logicalBytes: base.value.logicalLength,
        manifestBytes: base.value.manifest.bytes.length,
        partCount: base.value.chunks.length,
        throughputBytesPerSecond: throughputBytesPerSecond(base.value.logicalLength, base.elapsedMicroseconds),
        wholeFileSha256: base.value.wholeFileDigest.toString('hex'),
      },
      candidate: {
        generationMicroseconds: candidate.elapsedMicroseconds,
        ledger: candidate.value.ledger,
        logicalBytes: candidate.value.logicalLength,
        manifestBytes: candidate.value.manifest.bytes.length,
        partCount: candidate.value.chunks.length,
        throughputBytesPerSecond: throughputBytesPerSecond(candidate.value.logicalLength, candidate.elapsedMicroseconds),
        wholeFileSha256: candidate.value.wholeFileDigest.toString('hex'),
      },
      class: definition.class,
      compare: {
        ...comparison.value,
        compareMicroseconds: comparison.elapsedMicroseconds,
        throughputBytesPerSecond: throughputBytesPerSecond(candidate.value.logicalLength, comparison.elapsedMicroseconds),
      },
      deltas: {
        manifestBytesDelta: candidate.value.manifest.bytes.length - base.value.manifest.bytes.length,
        mutationStartByte: prefixBytes,
        partCountDelta: candidate.value.chunks.length - base.value.chunks.length,
        resynchronizationDistanceBytes,
        reusedRatioPartsPerMillion: Math.floor((Number(comparison.value.reusedBytes) * 1_000_000) / Math.max(1, candidate.value.logicalLength)),
        sharedPrefixBytes: prefixBytes,
        sharedSuffixBytes: suffixBytes,
      },
      description: definition.description,
      exactScaleExecuted: false,
      mutationKind: definition.mutationKind,
      schemaVersion: 'ogvcs.chunking/selection-workload-report/v1',
      success: true,
      workloadId: definition.workloadId,
      verify: {
        ...verification.value,
        verifyMicroseconds: verification.elapsedMicroseconds,
        throughputBytesPerSecond: throughputBytesPerSecond(candidate.value.logicalLength, verification.elapsedMicroseconds),
      },
    });
  }
  const thresholdEvaluations = evaluateThresholds(thresholdFile, workloads);
  const gateFailed = thresholdEvaluations.some(({ severity, status }) => severity === 'gate' && status === 'failed');
  const warningCount = thresholdEvaluations.filter(({ severity, status }) => severity === 'warning' && status === 'failed').length;
  const workloadSetDigest = sha256(workloadFile.workloads);
  const summary = {
    accountingMismatchCount: workloads.filter(({ accounting }) => !accounting.balanced).length,
    baseLogicalBytes: workloads.reduce((sum, row) => sum + row.base.logicalBytes, 0),
    candidateLogicalBytes: workloads.reduce((sum, row) => sum + row.candidate.logicalBytes, 0),
    exactScaleExecuted: false,
    successCount: workloads.filter(({ success }) => success).length,
    totalNewlyRequiredBytes: workloads.reduce((sum, row) => sum + Number(row.compare.newlyRequiredBytes), 0),
    totalReusedBytes: workloads.reduce((sum, row) => sum + Number(row.compare.reusedBytes), 0),
    warningCount,
    workloadCount: workloads.length,
  };
  const reportBody = {
    contractManifestSha256: contract.artifacts ? sha256(await readFile(join(SPEC_ROOT, 'manifest.json'))) : contract.manifestSha256,
    exactScaleExecuted: false,
    generatedAt: new Date().toISOString(),
    host: { architecture: process.arch, node: process.versions.node, os: process.platform },
    implementation: {
      id: '@opengamevcs/chunking-manifest/javascript',
      package: packageJson.name,
      version: packageJson.version,
    },
    overallStatus: gateFailed ? 'failed' : 'passed',
    profile: contract.profile,
    scalarWorkingMemoryBytesMinimum: LIMITS.scalarWorkingMinimum,
    schemaVersion: 'ogvcs.chunking/selection-benchmark-report/v1',
    sourceRevision: process.env.OGVCS_SOURCE_STATE ?? process.env.GITHUB_SHA ?? 'working-tree',
    summary,
    thresholdEvaluations,
    thresholdFile,
    thresholdFileDigest: sha256(thresholdFile),
    workloadDefinitionsDigest: workloadSetDigest,
    workloads,
  };
  return { ...reportBody, reportSha256: sha256(reportBody) };
}

async function main() {
  const output = parseArguments(process.argv.slice(2));
  const report = await buildChunkingSelectionReport();
  await mkdir(dirname(output), { recursive: true });
  await writeFile(output, `${canonicalJson(report)}\n`, { encoding: 'utf8', flag: 'w' });
  process.stdout.write(`${canonicalJson(report)}\n`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  await main();
}
