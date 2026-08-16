#!/usr/bin/env node

import { stat, mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';

const ONE_GIB = 1_073_741_824;
const MAX_REPORT_BYTES = 1_048_576;
const EXPECTED = Object.freeze({
  blockHex: '8e5a7fde9a212a4bdab640aaa5541de91d981498ac28bc8d8a901722ca807a24',
  chunkBytes: 1_048_576,
  chunkObjectRef: 'ogvcs:v1:chunk:sha256:8d40b35dab2f8ff4305af64230cecf10c9c7616c2ca75e606ced44114aa9224a',
  chunks: 1_048_576,
  logicalBytes: '1099511627776',
  manifestSeedHex: '860f753350ec981c19f401b44ed6a36a0ac76353a5389e31dc36048dd2d78f65',
  rawChunkSha256Hex: '223066858638b498e56e28ecc6fb8a0cd5d1c7d1ac99c3c4ce286df776bedc3f',
  treeEntries: 1_000_000,
  treeSeedHex: 'a73b9b82eb035d7f2d8bbfa98a94b71be16360dacc1b22a5c2d28bf5fa56fc80'
});

function parseArguments(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (!['--javascript', '--rust', '--output'].includes(name) || value === undefined || values.has(name)) {
      throw new Error('usage: node tools/compare-object-model-scale.mjs --javascript <report> --rust <report> --output <report>');
    }
    values.set(name, resolve(value));
  }
  if (values.size !== 3) throw new Error('all scale comparison paths are required');
  return { javascript: values.get('--javascript'), rust: values.get('--rust'), output: values.get('--output') };
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

async function boundedJson(path) {
  const metadata = await stat(path);
  if (!metadata.isFile() || metadata.size > MAX_REPORT_BYTES) throw new Error(`invalid scale report file: ${path}`);
  return JSON.parse(await readFile(path, 'utf8'));
}

function equal(left, right, field) {
  if (left !== right) throw new Error(`cross-language scale mismatch: ${field}`);
  return left;
}

function digest(left, right, field) {
  const value = equal(left, right, field);
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) {
    throw new Error(`${field} is not a lowercase SHA-256 digest`);
  }
  return value;
}

function objectRef(left, right, kind, field) {
  const value = equal(left, right, field);
  if (typeof value !== 'string' ||
      !new RegExp(`^ogvcs:v1:${kind}:sha256:[0-9a-f]{64}$`).test(value)) {
    throw new Error(`${field} is not the expected typed ObjectRef`);
  }
  return value;
}

function byteCount(left, right, field) {
  const value = equal(left, right, field);
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error(`${field} is not a positive safe integer`);
  return value;
}

function duration(value, field) {
  if (typeof value !== 'string' || !/^[1-9][0-9]*$/.test(value)) {
    throw new Error(`${field} is not a positive integer nanosecond count`);
  }
}

function belowLimit(value, field, { nullable = false } = {}) {
  if (nullable && value === null) return null;
  if (!Number.isSafeInteger(value) || value <= 0 || value >= ONE_GIB) throw new Error(`${field} is not positive and below 1 GiB`);
  return value;
}

function requireRevision(javascript, rust) {
  const revision = equal(javascript.sourceRevision, rust.sourceRevision, 'source revision');
  if (typeof revision !== 'string' || !/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(revision)) {
    throw new Error('exact scale reports must identify one lowercase Git object ID');
  }
  return revision;
}

async function main() {
  const paths = parseArguments(process.argv.slice(2));
  const javascript = await boundedJson(paths.javascript);
  const rust = await boundedJson(paths.rust);
  if (javascript.schema !== 'ogvcs.object-model.javascript-scale-report/v1' ||
      rust.schema !== 'ogvcs.object-model.rust-scale-report/v1' ||
      javascript.exactV1Scale !== true || rust.exactV1Scale !== true) {
    throw new Error('reports are not exact format-v1 scale evidence');
  }
  const sourceRevision = requireRevision(javascript, rust);
  if (javascript.packagedCli?.name !== '@opengamevcs/object-model' ||
      typeof javascript.packagedCli.version !== 'string' ||
      !/^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/.test(javascript.packagedCli.version) ||
      typeof javascript.packagedCli.tarballSha256Hex !== 'string' ||
      !/^[0-9a-f]{64}$/.test(javascript.packagedCli.tarballSha256Hex)) {
    throw new Error('JavaScript exact scale report does not identify its packed CLI artifact');
  }

  equal(javascript.recurrence.tree.seedHex, EXPECTED.treeSeedHex, 'tree seed');
  equal(rust.recurrence.treeSeedHex, EXPECTED.treeSeedHex, 'Rust tree seed');
  equal(javascript.recurrence.manifest.seedHex, EXPECTED.manifestSeedHex, 'manifest seed');
  equal(rust.recurrence.manifestSeedHex, EXPECTED.manifestSeedHex, 'Rust manifest seed');
  equal(javascript.recurrence.manifest.blockHex, EXPECTED.blockHex, 'manifest block');
  equal(rust.recurrence.manifestBlockHex, EXPECTED.blockHex, 'Rust manifest block');

  equal(javascript.tree.entries, EXPECTED.treeEntries, 'JavaScript tree count');
  equal(rust.tree.entries, EXPECTED.treeEntries, 'Rust tree count');
  const treeObjectRef = objectRef(javascript.tree.objectRef, rust.tree.objectRef, 'tree', 'tree ObjectRef');
  const treeOutputBytes = byteCount(javascript.tree.outputBytes, rust.tree.outputBytes, 'tree output bytes');
  const treePayloadSha256Hex = digest(
    javascript.tree.payloadSha256Hex, rust.tree.payloadSha256Hex, 'tree payload SHA-256');
  equal(String(javascript.tree.summary.logicalBytes), rust.tree.logicalBytes, 'tree logical-byte summary');
  if (javascript.tree.byteForByteParity !== true || rust.tree.byteForByteParity !== true ||
      javascript.tree.fileIdUniqueness?.orderedDiskIndex !== 'verified' ||
      javascript.tree.fileIdUniqueness?.sortedSideIndex !== 'verified' ||
      javascript.tree.fileIdUniqueness?.cliDiskIndex !== 'verified' ||
      rust.tree.fileIdUniqueness !== 'verified-exact-disk-index' ||
      javascript.tree.cliVerification.status !== 'valid' || javascript.tree.cliVerification.objectRef !== treeObjectRef) {
    throw new Error('tree byte parity, CLI verification, or uniqueness proof is incomplete');
  }
  duration(javascript.tree.orderedWallTimeNanoseconds, 'JavaScript ordered-tree duration');
  duration(javascript.tree.sortedWallTimeNanoseconds, 'JavaScript sorted-tree duration');
  duration(rust.tree.orderedWallTimeNanoseconds, 'Rust ordered-tree duration');
  duration(rust.tree.sortedWallTimeNanoseconds, 'Rust sorted-tree duration');

  for (const [report, name] of [[javascript, 'JavaScript'], [rust, 'Rust']]) {
    equal(report.manifest.chunks, EXPECTED.chunks, `${name} manifest count`);
    equal(report.manifest.chunkBytes, EXPECTED.chunkBytes, `${name} chunk bytes`);
    equal(report.manifest.chunkObjectRef, EXPECTED.chunkObjectRef, `${name} chunk ObjectRef`);
    equal(report.manifest.rawChunkSha256Hex, EXPECTED.rawChunkSha256Hex, `${name} raw chunk SHA-256`);
    equal(report.manifest.logicalBytes, EXPECTED.logicalBytes, `${name} logical bytes`);
  }
  const wholeFileDigestHex = digest(
    javascript.manifest.wholeFileDigestHex, rust.manifest.wholeFileDigestHex, 'whole-file digest');
  const manifestObjectRef = objectRef(
    javascript.manifest.objectRef, rust.manifest.objectRef, 'content-manifest', 'manifest ObjectRef');
  const manifestOutputBytes = byteCount(
    javascript.manifest.outputBytes, rust.manifest.outputBytes, 'manifest output bytes');
  const manifestPayloadSha256Hex = digest(
    javascript.manifest.payloadSha256Hex, rust.manifest.payloadSha256Hex, 'manifest payload SHA-256');
  if (javascript.manifest.verification.contentVerified !== true || javascript.manifest.structuralOnly !== false ||
      rust.manifest.contentVerified !== true) {
    throw new Error('one or both manifests were not content-verified');
  }
  duration(javascript.manifest.wallTimeNanoseconds, 'JavaScript manifest duration');
  duration(rust.manifest.wallTimeNanoseconds, 'Rust manifest duration');

  const comparison = {
    identity: {
      chunkObjectRef: EXPECTED.chunkObjectRef,
      manifestObjectRef,
      manifestOutputBytes,
      manifestPayloadSha256Hex,
      rawChunkSha256Hex: EXPECTED.rawChunkSha256Hex,
      treeObjectRef,
      treeOutputBytes,
      treePayloadSha256Hex,
      wholeFileDigestHex
    },
    resources: {
      javascriptCliMaxRssBytes: belowLimit(javascript.tree.cliVerification.processMaxRssBytes, 'JavaScript CLI RSS'),
      javascriptCliPeakScratchBytes: belowLimit(javascript.tree.cliVerification.peakScratchBytes, 'JavaScript CLI scratch'),
      javascriptMaxRssBytes: belowLimit(javascript.process.maxRssBytes, 'JavaScript RSS'),
      javascriptOrderedFileIdScratchBytes: belowLimit(javascript.tree.orderedFileIdPeakScratchBytes, 'JavaScript ordered FileID scratch'),
      javascriptSortedScratchBytes: belowLimit(javascript.tree.sortedPeakScratchBytes, 'JavaScript sorted scratch'),
      rustMaxRssBytes: belowLimit(rust.process.maxRssBytes, 'Rust RSS'),
      rustOrderedFileIdScratchBytes: belowLimit(rust.tree.orderedFileIdPeakScratchBytes, 'Rust ordered FileID scratch'),
      rustSortedScratchBytes: belowLimit(rust.tree.sortedPeakScratchBytes, 'Rust sorted scratch')
    },
    packagedCli: {
      name: javascript.packagedCli.name,
      tarballSha256Hex: javascript.packagedCli.tarballSha256Hex,
      version: javascript.packagedCli.version
    },
    result: 'byte-identical-and-bounded',
    schema: 'ogvcs.object-model.scale-comparison/v1',
    sourceRevision
  };
  await mkdir(dirname(paths.output), { recursive: true });
  await writeFile(paths.output, `${canonicalJson(comparison)}\n`, { encoding: 'utf8', flag: 'wx' });
  process.stdout.write(`${canonicalJson(comparison)}\n`);
}

await main();
