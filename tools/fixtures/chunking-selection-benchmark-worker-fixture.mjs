#!/usr/bin/env node

import process from 'node:process';

import { canonicalJson } from '../chunking-selection-benchmark-common.mjs';

function usage() {
  throw new Error('usage: node tools/fixtures/chunking-selection-benchmark-worker-fixture.mjs --mode <mode> --workload-id <id>');
}

function parseArguments(argv) {
  if (argv.length !== 4 || argv[0] !== '--mode' || argv[2] !== '--workload-id' || argv[1].length === 0 || argv[3].length === 0) usage();
  return { mode: argv[1], workloadId: argv[3] };
}

function successCapture(workloadId) {
  return canonicalJson({
    host: { architecture: process.arch, node: process.versions.node, os: process.platform },
    process: {
      maxRssBytes: 1,
      maxRssSource: 'node:process.resourceUsage().maxRSS (reported KiB)',
      peakMemoryBytes: 1,
      sampleIntervalMs: 5,
      sampledPeakRssBytes: 1,
      systemCpuMicroseconds: 1,
      totalWallMicroseconds: 1,
      userCpuMicroseconds: 1,
    },
    schemaVersion: 'ogvcs.chunking/selection-workload-capture/v1',
    success: true,
    workload: {
      accounting: { balanced: true, schemaVersion: 'ogvcs.chunking/selection-benchmark-accounting/v1' },
      base: { generationMicroseconds: 0, ledger: { memoryBytes: 0, peakMemoryBytes: 0, peakScratchBytes: 0, records: 0, scratchBytes: 0, spilled: false }, logicalBytes: 0, manifestBytes: 0, partCount: 0, throughputBytesPerSecond: 0, wholeFileSha256: '0'.repeat(64) },
      candidate: { generationMicroseconds: 0, ledger: { memoryBytes: 0, peakMemoryBytes: 0, peakScratchBytes: 0, records: 0, scratchBytes: 0, spilled: false }, logicalBytes: 0, manifestBytes: 0, partCount: 0, throughputBytesPerSecond: 0, wholeFileSha256: '0'.repeat(64) },
      class: 'append',
      compare: { compareMicroseconds: 0, ledger: { memoryBytes: 0, peakMemoryBytes: 0, peakScratchBytes: 0, records: 0, scratchBytes: 0, spilled: false }, logicalBytes: '0', manifestObjectId: 'ogvcs:v1:content-manifest:sha256:'.concat('0'.repeat(64)), newlyRequiredBytes: '0', partCount: 0, repeatedBytes: '0', reusedBytes: '0', throughputBytesPerSecond: 0, uniqueBytes: '0', uniqueChunks: 0 },
      deltas: { manifestBytesDelta: 0, mutationStartByte: 0, partCountDelta: 0, resynchronization: { firstAlignedBaseChunkIndex: null, firstAlignedBaseOffset: null, firstAlignedCandidateChunkIndex: null, firstAlignedCandidateOffset: null, firstAlignedChunkObjectId: null, metric: 'no-post-mutation-aligned-reused-chunk', resynchronizationDistanceBytes: null, schemaVersion: 'ogvcs.chunking/resynchronization-summary/v1' }, reusedRatioPartsPerMillion: 0 },
      description: 'fixture',
      exactScaleExecuted: false,
      mutationKind: 'append',
      schemaVersion: 'ogvcs.chunking/selection-workload-report/v1',
      success: true,
      verify: { ledger: { memoryBytes: 0, peakMemoryBytes: 0, peakScratchBytes: 0, records: 0, scratchBytes: 0, spilled: false }, logicalBytes: '0', manifestObjectId: 'ogvcs:v1:content-manifest:sha256:'.concat('0'.repeat(64)), partCount: 0, providerReads: 0, repeatedBytes: '0', throughputBytesPerSecond: 0, uniqueBytes: '0', verifyMicroseconds: 0 },
      workloadId,
    },
    workloadId,
  });
}

async function main() {
  const { mode, workloadId } = parseArguments(process.argv.slice(2));
  switch (mode) {
    case 'timeout':
      await new Promise((resolve) => setTimeout(resolve, 250));
      break;
    case 'invalid-json':
      process.stdout.write('{');
      break;
    case 'overflow':
      process.stdout.write('x'.repeat(8192));
      break;
    case 'exit-mismatch':
      process.stdout.write(`${successCapture(workloadId)}\n`);
      process.exitCode = 1;
      break;
    default:
      usage();
  }
}

await main();
