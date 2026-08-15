import assert from 'node:assert/strict';
import { lstat, mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import test from 'node:test';

import {
  generateFixture,
  planFixture,
  referenceScaleRequest,
  verifyFixture,
} from '../src/index.mjs';

const runScale = process.env.OGVCS_RUN_SCALE === '1';

async function measureArtifactBytes(target) {
  const metadata = await lstat(target);
  let apparent = metadata.isFile() ? metadata.size : 0;
  let allocated = Number.isSafeInteger(metadata.blocks) ? metadata.blocks * 512 : null;
  if (metadata.isDirectory()) {
    for (const entry of await readdir(target)) {
      const child = await measureArtifactBytes(path.join(target, entry));
      apparent += child.apparent;
      allocated = allocated === null || child.allocated === null
        ? null
        : allocated + child.allocated;
    }
  }
  return { allocated, apparent };
}

test('reference scale derives one million paths and streams every byte of a 100-GiB mutable file below 1 GiB RSS', {
  skip: runScale ? false : 'set OGVCS_RUN_SCALE=1 to run the reference-scale acceptance test',
  timeout: 75 * 60 * 1000,
}, async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'ogvcs-fixture-scale-'));
  t.after(() => rm(root, { force: true, recursive: true }));
  const request = referenceScaleRequest('fixture');
  const plan = planFixture(request);
  assert.equal(request.scale.pathCount, 1_000_000);
  assert.equal(request.scale.largeFileBytes, 100 * 1024 ** 3);
  assert.equal(plan.representation.materialization, 'index-only');
  assert.equal(plan.representation.largeFileMode, 'stream-verified');
  assert.equal(plan.estimates.materializedPathCount, 0);
  assert.equal(plan.estimates.streamedLargeBytes, String(600 * 1024 ** 3));
  assert.ok(BigInt(plan.estimates.peakGeneratorMemoryBytes) < 1024n ** 3n);

  const started = performance.now();
  const generationStarted = performance.now();
  const generated = await generateFixture(request, { cwd: root });
  const generationDurationMilliseconds = Math.round(performance.now() - generationStarted);
  const verificationStarted = performance.now();
  const verification = await verifyFixture('fixture', { cwd: root, deep: true });
  const verificationDurationMilliseconds = Math.round(performance.now() - verificationStarted);
  // resourceUsage().maxRSS is the operating-system process high-water mark in
  // KiB. Unlike an event-loop timer, it records peaks while synchronous
  // hashing/materialization loops are running.
  const osHighWaterRssBytes = process.resourceUsage().maxRSS * 1024;
  const currentRssBytes = process.memoryUsage().rss;
  const peakRss = Math.max(osHighWaterRssBytes, currentRssBytes);
  const durationMilliseconds = Math.round(performance.now() - started);
  const artifactBytes = await measureArtifactBytes(path.join(root, 'fixture'));

  assert.equal(generated.summary.paths, 1_000_000);
  assert.equal(verification.verified, true);
  assert.equal(verification.summary.failed, 0);
  const descriptor = JSON.parse(await readFile(path.join(root, 'fixture', 'large-file.json'), 'utf8'));
  assert.equal(descriptor.physical.mode, 'stream-verified');
  assert.equal(descriptor.physical.physicalBytes, 0);
  assert.equal(descriptor.physical.versionDigests.length, 3);
  assert.equal(descriptor.physical.streamedLogicalBytes, 300 * 1024 ** 3);
  assert.ok(descriptor.physical.versionDigests.every(({ bytes, digest }) => (
    bytes === 100 * 1024 ** 3 && /^[0-9a-f]{64}$/.test(digest)
  )));
  assert.equal(verification.summary.verifiedBytes, 300 * 1024 ** 3);
  assert.ok(
    peakRss <= Number(plan.estimates.peakGeneratorMemoryBytes),
    `peak RSS ${peakRss} exceeded the planned ${plan.estimates.peakGeneratorMemoryBytes}`,
  );
  assert.ok(peakRss < 1024 ** 3, `peak RSS ${peakRss} must remain below 1 GiB`);
  assert.ok(
    BigInt(artifactBytes.apparent) <= BigInt(plan.estimates.physicalArtifactBytes),
    `apparent artifact bytes ${artifactBytes.apparent} exceeded plan ${plan.estimates.physicalArtifactBytes}`,
  );
  if (artifactBytes.allocated !== null) {
    assert.ok(
      BigInt(artifactBytes.allocated) <= BigInt(plan.estimates.physicalArtifactBytes),
      `allocated artifact bytes ${artifactBytes.allocated} exceeded plan ${plan.estimates.physicalArtifactBytes}`,
    );
  }
  assert.ok(
    generationDurationMilliseconds <= plan.estimates.durationSeconds * 1000,
    `generation ${generationDurationMilliseconds}ms exceeded plan ${plan.estimates.durationSeconds}s`,
  );
  assert.ok(
    verificationDurationMilliseconds <= plan.estimates.standaloneVerificationDurationSeconds * 1000,
    `verification ${verificationDurationMilliseconds}ms exceeded plan ${plan.estimates.standaloneVerificationDurationSeconds}s`,
  );
  assert.ok(
    durationMilliseconds <= plan.estimates.acceptanceWorkflowDurationSeconds * 1000,
    `workflow ${durationMilliseconds}ms exceeded plan ${plan.estimates.acceptanceWorkflowDurationSeconds}s`,
  );

  console.log(JSON.stringify({
    allocatedArtifactBytes: artifactBytes.allocated,
    apparentArtifactBytes: artifactBytes.apparent,
    durationMilliseconds,
    generationDurationMilliseconds,
    logicalLargeFileBytes: request.scale.largeFileBytes,
    manifestDigest: generated.manifestDigest,
    osHighWaterRssBytes,
    pathCount: generated.summary.paths,
    peakRssBytes: peakRss,
    physicalLargeFileBytes: descriptor.physical.physicalBytes,
    platform: `${process.platform}-${process.arch}`,
    requestDigest: generated.requestDigest,
    streamedLogicalBytesDuringGeneration: descriptor.physical.streamedLogicalBytes,
    streamedLogicalBytesDuringExplicitVerification: verification.summary.verifiedBytes,
    verificationDurationMilliseconds,
    versionCount: descriptor.physical.versionDigests.length,
  }));
});
