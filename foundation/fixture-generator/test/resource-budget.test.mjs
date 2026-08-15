import assert from 'node:assert/strict';
import { lstat, readdir } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

import { canonicalStringify } from '../src/canonical.mjs';
import {
  createRequest,
  generateFixture,
  inspectFixture,
  listProfiles,
  planFixture,
  referenceScaleRequest,
  verifyFixture,
} from '../src/index.mjs';
import { largeFileRecipe } from '../src/model.mjs';
import { ResourceBudget } from '../src/writer.mjs';
import { temporaryDirectory } from './test-helpers.mjs';

async function artifactBytes(directory) {
  let bytes = 0;
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const target = path.join(directory, entry.name);
    if (entry.isDirectory()) bytes += await artifactBytes(target);
    else if (entry.isFile()) bytes += (await lstat(target)).size;
  }
  return bytes;
}

test('resource ledger tracks durable artifacts, atomic peaks, writes, deadlines, and memory', async () => {
  const budget = new ResourceBudget({ maximumPhysicalBytes: 200 });
  budget.setArtifactBytes('inventory.ndjson', 60, { written: true });
  budget.setArtifactBytes('operations.ndjson', 30, { written: true });
  const atomic = budget.beginAtomicWrite('inventory.ndjson', 70);
  assert.equal(budget.physicalBytes, 90);
  assert.equal(budget.peakPhysicalBytes, 160);
  atomic.commit();
  assert.equal(budget.physicalBytes, 100);
  assert.equal(budget.totalWrittenBytes, 160);

  assert.throws(
    () => budget.beginAtomicWrite('groups.json', 101),
    (error) => error.type === 'resource-limit' && error.details.artifact === 'groups.json.tmp',
  );

  const expired = new ResourceBudget({ deadline: Date.now() - 1 });
  assert.throws(
    () => expired.checkRuntime('final-scenario'),
    (error) => error.type === 'resource-limit' && error.details.phase === 'final-scenario',
  );

  const memory = new ResourceBudget({ maximumMemoryBytes: process.memoryUsage().rss - 1 });
  assert.throws(
    () => memory.checkRuntime('prepublication-verification'),
    (error) => error.type === 'resource-limit'
      && error.details.phase === 'prepublication-verification',
  );

  const headroom = new ResourceBudget({ maximumMemoryGrowthBytes: 1024 });
  assert.throws(
    () => headroom.assertMemoryHeadroom(1025, 'manifest-preparse'),
    (error) => error.type === 'resource-limit'
      && error.details.phase === 'manifest-preparse'
      && error.details.additionalBytes === 1025,
  );
});

test('conservative plans cover every byte of representative semantic fixtures', async (t) => {
  const root = await temporaryDirectory(t, 'ogvcs-resource-plan-');
  for (const { id } of listProfiles()) {
    const request = createRequest({
      destination: id,
      extensions: {
        'generation.checkpoint-every': 11,
        'generation.large-file-mode': 'virtual',
        'generation.materialization': 'full',
      },
      profile: { id, version: '2.0.0' },
      scale: { historyOperationCount: 31, largeFileBytes: 0, maxDepth: 8, pathCount: 48 },
      seed: `resource-plan-${id}`,
    });
    const plan = planFixture(request);
    const breakdownBytes = Object.values(plan.estimates.physicalArtifactBreakdown)
      .reduce((total, value) => total + BigInt(value), 0n);
    assert.equal(breakdownBytes, BigInt(plan.estimates.physicalArtifactBytes));
    assert.equal(
      BigInt(plan.estimates.physicalArtifactBytes) + BigInt(plan.estimates.physicalTransientBytes),
      BigInt(plan.estimates.physicalBytes),
    );
    assert.ok(plan.estimates.runtimeBudgetedPhases.includes('mandatory-prepublication-verification'));
    assert.ok(plan.estimates.runtimeBudgetedPhases.includes('final-scenario-and-manifest'));
    await generateFixture(request, { cwd: root });
    const measured = await artifactBytes(path.join(root, id));
    assert.ok(
      BigInt(plan.estimates.physicalArtifactBytes) >= BigInt(measured),
      `${id}: measured ${measured} exceeds durable estimate ${plan.estimates.physicalArtifactBytes}`,
    );
    assert.ok(
      BigInt(plan.estimates.physicalBytes) >= BigInt(measured),
      `${id}: measured ${measured} exceeds peak estimate ${plan.estimates.physicalBytes}`,
    );
  }
});

test('memory plans scale with path and operation counts while reference scale remains below 1 GiB', () => {
  const tiny = planFixture(createRequest({
    scale: { historyOperationCount: 0, largeFileBytes: 0, maxDepth: 2, pathCount: 1 },
  }));
  const reference = planFixture(referenceScaleRequest());
  const maximum = planFixture(createRequest({
    scale: {
      historyOperationCount: 10_000_000,
      largeFileBytes: 0,
      maxDepth: 64,
      pathCount: 10_000_000,
    },
  }));
  assert.ok(
    BigInt(tiny.estimates.peakGeneratorMemoryBytes)
      < BigInt(reference.estimates.peakGeneratorMemoryBytes),
  );
  assert.ok(BigInt(reference.estimates.peakGeneratorMemoryBytes) < 1024n ** 3n);
  assert.equal(
    reference.estimates.standaloneVerificationMemoryGrowthBytes,
    reference.estimates.peakGeneratorMemoryBytes,
  );
  assert.ok(
    BigInt(reference.estimates.peakGeneratorMemoryBytes)
      < BigInt(maximum.estimates.peakGeneratorMemoryBytes),
  );

  const shallowCode = planFixture(createRequest({
    profile: { id: 'code-heavy', version: '2.0.0' },
    scale: { historyOperationCount: 0, largeFileBytes: 0, maxDepth: 4, pathCount: 10_000 },
  }));
  const deepCode = planFixture(createRequest({
    profile: { id: 'code-heavy', version: '2.0.0' },
    scale: { historyOperationCount: 0, largeFileBytes: 0, maxDepth: 64, pathCount: 10_000 },
  }));
  assert.ok(
    BigInt(deepCode.estimates.peakGeneratorMemoryBytes)
      > BigInt(shallowCode.estimates.peakGeneratorMemoryBytes) + 200n * 1024n ** 2n,
  );

  const globalScale = {
    historyOperationCount: 600_000,
    largeFileBytes: 0,
    maxDepth: 2,
    pathCount: 1,
  };
  const fullGlobal = planFixture(createRequest({
    profile: { id: 'global-studio', version: '2.0.0' },
    scale: globalScale,
  }));
  const minimalGlobal = planFixture(createRequest({
    featureFlags: {
      'branch-update': false,
      'ci-materialization': false,
      interruptions: false,
      'lock-lifecycle': false,
      'network-conditions': false,
      review: false,
      'selective-sync': false,
    },
    profile: { id: 'global-studio', version: '2.0.0' },
    scale: globalScale,
  }));
  assert.ok(
    BigInt(minimalGlobal.estimates.peakGeneratorMemoryBytes)
      > BigInt(fullGlobal.estimates.peakGeneratorMemoryBytes) + 90n * 1024n ** 2n,
  );
});

test('maximum-version descriptor serialization fits its named plan breakdown', () => {
  const request = createRequest({
    extensions: {
      'generation.large-file-mode': 'virtual',
      'generation.materialization': 'index-only',
      'generation.mutable-versions': 64,
    },
    profile: { id: 'large-binary', version: '2.0.0' },
    scale: {
      historyOperationCount: 0,
      largeFileBytes: 1024 ** 4,
      maxDepth: 4,
      pathCount: 1,
    },
  });
  const recipe = largeFileRecipe(request, 'Assets/Binary/Mutable/hero-source.bin');
  const descriptorBytes = Buffer.byteLength(`${canonicalStringify({
    ...recipe,
    descriptorDigest: '0'.repeat(64),
    physical: { mode: 'virtual', physicalBytes: 0 },
  })}\n`);
  assert.ok(
    BigInt(planFixture(request).estimates.physicalArtifactBreakdown.largeDescriptor)
      >= BigInt(descriptorBytes),
  );
});

test('duration plans include verified recovery replay and rebuild work', () => {
  const request = createRequest({
    extensions: {
      'generation.large-file-mode': 'full',
      'generation.materialization': 'full',
    },
    profile: { id: 'large-binary', version: '2.0.0' },
    scale: {
      historyOperationCount: 20_000,
      largeFileBytes: 1024 ** 3,
      maxDepth: 4,
      pathCount: 30_000,
    },
  });
  const estimates = planFixture(request).estimates;
  const phases = estimates.durationPhaseSeconds;
  assert.ok(phases.pathRecoveryReplayAndRebuild > 0);
  assert.ok(phases.operationRecoveryReplay > 0);
  assert.equal(phases.fullLargeRecoveryReplay, Math.ceil(1024 ** 3 / (250 * 1024 ** 2)));
  assert.ok(estimates.standaloneVerificationDurationSeconds > 0);
  assert.equal(
    estimates.acceptanceWorkflowDurationSeconds,
    estimates.durationSeconds + estimates.standaloneVerificationDurationSeconds,
  );
});

test('planned physical and elapsed ceilings reject before workspace creation', async (t) => {
  const root = await temporaryDirectory(t, 'ogvcs-resource-reject-');
  const base = createRequest({
    destination: 'fixture',
    extensions: {
      'generation.large-file-mode': 'virtual',
      'generation.materialization': 'index-only',
    },
    scale: { historyOperationCount: 8, largeFileBytes: 0, maxDepth: 4, pathCount: 16 },
  });
  const plan = planFixture(base);
  const physicalRequest = createRequest({
    ...base,
    resourceLimits: { maximumPhysicalBytes: Number(plan.estimates.physicalBytes) - 1 },
  });
  await assert.rejects(
    generateFixture(physicalRequest, { cwd: root }),
    (error) => error.type === 'resource-limit' && /maximumPhysicalBytes/u.test(error.message),
  );

  const elapsedRequest = createRequest({
    ...base,
    resourceLimits: { maximumDurationSeconds: Math.max(1, plan.estimates.durationSeconds - 1) },
  });
  if (elapsedRequest.resourceLimits.maximumDurationSeconds < plan.estimates.durationSeconds) {
    await assert.rejects(
      generateFixture(elapsedRequest, { cwd: root }),
      (error) => error.type === 'resource-limit' && /maximumDurationSeconds/u.test(error.message),
    );
  }

  await assert.rejects(lstat(path.join(root, 'fixture')), { code: 'ENOENT' });
});

test('sparse large files reserve their full logical size against portable physical limits', async (t) => {
  const root = await temporaryDirectory(t, 'ogvcs-resource-sparse-');
  const request = createRequest({
    destination: 'fixture',
    extensions: {
      'generation.large-file-mode': 'sparse',
      'generation.materialization': 'index-only',
    },
    profile: { id: 'large-binary', version: '2.0.0' },
    scale: { historyOperationCount: 2, largeFileBytes: 64 * 1024 * 1024, maxDepth: 4, pathCount: 3 },
  });
  const plan = planFixture(request);
  assert.equal(
    plan.estimates.physicalArtifactBreakdown.materializedLargeFile,
    String(request.scale.largeFileBytes),
  );
  const limited = createRequest({
    ...request,
    resourceLimits: { maximumPhysicalBytes: Number(plan.estimates.physicalBytes) - 1 },
  });
  await assert.rejects(
    generateFixture(limited, { cwd: root }),
    (error) => error.type === 'resource-limit' && /maximumPhysicalBytes/u.test(error.message),
  );
  await assert.rejects(lstat(path.join(root, 'fixture')), { code: 'ENOENT' });
});

test('a runtime-budget failure inside mandatory verification is propagated without publication', async (t) => {
  const root = await temporaryDirectory(t, 'ogvcs-resource-verify-');
  const request = createRequest({
    destination: 'fixture',
    extensions: {
      'generation.checkpoint-every': 4,
      'generation.large-file-mode': 'virtual',
      'generation.materialization': 'index-only',
    },
    scale: { historyOperationCount: 6, largeFileBytes: 0, maxDepth: 4, pathCount: 12 },
  });
  await assert.rejects(
    generateFixture(request, {
      cwd: root,
      env: { OGVCS_FIXTURE_TEST_FAIL_RUNTIME_PHASE: 'verification:ndjson-record' },
    }),
    (error) => error.type === 'resource-limit'
      && error.details.phase === 'verification:ndjson-record',
  );
  await assert.rejects(lstat(path.join(root, 'fixture', 'manifest.json')), { code: 'ENOENT' });
  const stage = (await readdir(root)).find((name) => name.endsWith('.stage'));
  assert.ok(stage, 'mandatory verification failure must preserve the owned resumable stage');
  assert.ok((await lstat(path.join(root, stage, 'manifest.json'))).isFile());
});

test('standalone verification constructs and enforces its own resource budget', async (t) => {
  const root = await temporaryDirectory(t, 'ogvcs-resource-standalone-verify-');
  const request = createRequest({
    destination: 'fixture',
    extensions: {
      'generation.large-file-mode': 'virtual',
      'generation.materialization': 'index-only',
    },
    scale: { historyOperationCount: 2, largeFileBytes: 0, maxDepth: 2, pathCount: 3 },
  });
  await generateFixture(request, { cwd: root });
  await assert.rejects(
    verifyFixture('fixture', {
      cwd: root,
      env: { OGVCS_FIXTURE_TEST_FAIL_RUNTIME_PHASE: 'verification:start' },
    }),
    (error) => error.type === 'resource-limit'
      && error.details.phase === 'verification:start',
  );
  await assert.rejects(
    verifyFixture('fixture', {
      cwd: root,
      env: { OGVCS_FIXTURE_TEST_FAIL_RUNTIME_PHASE: 'manifest-preparse' },
    }),
    (error) => error.type === 'resource-limit'
      && error.details.phase === 'manifest-preparse',
  );
});

test('inspection bootstraps a resource budget before manifest parsing', async (t) => {
  const root = await temporaryDirectory(t, 'ogvcs-resource-inspection-');
  const request = createRequest({
    destination: 'fixture',
    extensions: {
      'generation.large-file-mode': 'virtual',
      'generation.materialization': 'index-only',
    },
    scale: { historyOperationCount: 2, largeFileBytes: 0, maxDepth: 2, pathCount: 3 },
  });
  await generateFixture(request, { cwd: root });
  await assert.rejects(
    inspectFixture('fixture', {
      cwd: root,
      env: { OGVCS_FIXTURE_TEST_FAIL_RUNTIME_PHASE: 'manifest-preparse' },
    }),
    (error) => error.type === 'resource-limit'
      && error.details.phase === 'manifest-preparse',
  );
});
