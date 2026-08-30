#!/usr/bin/env node

import process from 'node:process';

import {
  buildChunkingSelectionWorkload,
  canonicalJson,
  loadSelectionAuthority,
} from './chunking-selection-benchmark-common.mjs';

function parseArguments(argv) {
  if (argv.length !== 2 || argv[0] !== '--workload-id' || argv[1].length === 0) {
    throw new Error('usage: node tools/chunking-selection-benchmark-worker.mjs --workload-id <id>');
  }
  return argv[1];
}

function osHighWaterRssBytes() {
  const maxRss = process.resourceUsage?.().maxRSS;
  return Number.isSafeInteger(maxRss) && maxRss > 0 ? maxRss * 1024 : 0;
}

function startPeakTracker(sampleIntervalMs = 5) {
  let sampledPeakRssBytes = process.memoryUsage().rss;
  const interval = setInterval(() => {
    sampledPeakRssBytes = Math.max(sampledPeakRssBytes, process.memoryUsage().rss, osHighWaterRssBytes());
  }, sampleIntervalMs);
  interval.unref?.();
  return {
    finish() {
      clearInterval(interval);
      sampledPeakRssBytes = Math.max(sampledPeakRssBytes, process.memoryUsage().rss, osHighWaterRssBytes());
      const maxRssBytes = osHighWaterRssBytes();
      return {
        peakMemoryBytes: Math.max(sampledPeakRssBytes, maxRssBytes),
        sampleIntervalMs,
        sampledPeakRssBytes,
        maxRssBytes,
        maxRssSource: maxRssBytes > 0 ? 'node:process.resourceUsage().maxRSS (reported KiB)' : 'unavailable',
      };
    },
  };
}

async function main() {
  const workloadId = parseArguments(process.argv.slice(2));
  const startedWall = process.hrtime.bigint();
  const startedCpu = process.cpuUsage();
  const tracker = startPeakTracker();
  try {
    const { workloadFile } = await loadSelectionAuthority();
    const definition = workloadFile.workloads.find((row) => row.workloadId === workloadId);
    if (!definition) throw new Error(`unknown workload ${workloadId}`);
    const workload = await buildChunkingSelectionWorkload(definition);
    const endedCpu = process.cpuUsage(startedCpu);
    const processPeak = tracker.finish();
    const totalWallMicroseconds = Number((process.hrtime.bigint() - startedWall) / 1000n);
    process.stdout.write(`${canonicalJson({
      schemaVersion: 'ogvcs.chunking/selection-workload-capture/v1',
      workloadId,
      success: true,
      host: { architecture: process.arch, node: process.versions.node, os: process.platform },
      process: {
        ...processPeak,
        systemCpuMicroseconds: endedCpu.system,
        userCpuMicroseconds: endedCpu.user,
        totalWallMicroseconds,
      },
      workload,
    })}\n`);
  } catch (error) {
    const endedCpu = process.cpuUsage(startedCpu);
    const processPeak = tracker.finish();
    const totalWallMicroseconds = Number((process.hrtime.bigint() - startedWall) / 1000n);
    process.stdout.write(`${canonicalJson({
      schemaVersion: 'ogvcs.chunking/selection-workload-capture/v1',
      workloadId,
      success: false,
      host: { architecture: process.arch, node: process.versions.node, os: process.platform },
      process: {
        ...processPeak,
        systemCpuMicroseconds: endedCpu.system,
        userCpuMicroseconds: endedCpu.user,
        totalWallMicroseconds,
      },
      error: {
        code: typeof error?.code === 'string' ? error.code : 'HARNESS_DRIVER_FAILED',
        message: error instanceof Error ? error.message : String(error),
        name: error instanceof Error ? error.name : 'Error',
      },
    })}\n`);
    process.exitCode = 1;
  }
}

await main();
