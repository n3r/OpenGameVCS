import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, readdir, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const ordinaryPath = new URL('../.github/workflows/object-model.yml', import.meta.url);
const scalePath = new URL('../.github/workflows/object-model-scale.yml', import.meta.url);
const workflowDirectory = new URL('../.github/workflows/', import.meta.url);
const completionEvidencePath = new URL(
  '../docs/evidence/OGVCS-002/completion-2026-08-24.json', import.meta.url
);
const scaleComparatorPath = new URL('./compare-object-model-scale.mjs', import.meta.url);
const evidenceReadmePath = new URL('../docs/evidence/OGVCS-002/README.md', import.meta.url);
const completedPrdPath = new URL(
  '../prd/done/OGVCS-002-core-object-library-repository-format.md', import.meta.url
);
const formatReadmePath = new URL('../spec/repository-format/v1/README.md', import.meta.url);
const encodingPath = new URL('../spec/repository-format/v1/encoding.md', import.meta.url);
const NODE_24_ACTION_PINS = new Map([
  ['checkout', '3d3c42e5aac5ba805825da76410c181273ba90b1'], // v7.0.1
  ['setup-node', '820762786026740c76f36085b0efc47a31fe5020'], // v7.0.0
  ['upload-artifact', '043fb46d1a93c77aae656e7c1c64a875d1fc6a0a'], // v7.0.1
  ['download-artifact', '3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c'] // v8.0.1
]);

test('official JavaScript actions use immutable Node 24-compatible releases', async () => {
  const workflowFiles = (await readdir(workflowDirectory))
    .filter((name) => name.endsWith('.yml') || name.endsWith('.yaml'))
    .sort();
  let checkedUses = 0;

  for (const workflowFile of workflowFiles) {
    const source = await readFile(new URL(workflowFile, workflowDirectory), 'utf8');
    for (const match of source.matchAll(
      /uses:\s+actions\/(checkout|setup-node|upload-artifact|download-artifact)@([^\s#]+)/g
    )) {
      const [, action, reference] = match;
      checkedUses += 1;
      assert.equal(
        reference,
        NODE_24_ACTION_PINS.get(action),
        `${workflowFile}: actions/${action} must use the reviewed Node 24-compatible commit`
      );
    }
  }

  assert.ok(checkedUses > 0, 'expected at least one reviewed official JavaScript action');
});

test('exact object-model scale is isolated from ordinary pull-request and branch CI', async () => {
  const [ordinary, scale] = await Promise.all([
    readFile(ordinaryPath, 'utf8'),
    readFile(scalePath, 'utf8')
  ]);

  assert.match(ordinary, /\n  pull_request:\n/);
  assert.match(ordinary, /\n  push:\n    branches:\n/);
  assert.doesNotMatch(ordinary, /run-scale\.mjs/);
  assert.doesNotMatch(ordinary, /release_scale_tree_and_one_tib_manifest/);
  assert.doesNotMatch(ordinary, /ogvcs-002-scale-/);
  assert.doesNotMatch(ordinary, /run_scale/);

  const triggerEnd = scale.indexOf('\npermissions:');
  assert.notEqual(triggerEnd, -1);
  const triggers = scale.slice(0, triggerEnd);
  assert.match(
    triggers,
    /\n  workflow_dispatch:\n    inputs:\n      confirm_exact_scale:\n(?:        .+\n)+?        required: true\n        type: boolean\n        default: false\n/
  );
  assert.match(triggers, /\n  push:\n    tags:\n      - "ogvcs-002-scale-\*"\n/);
  assert.doesNotMatch(triggers, /pull_request:/);
  assert.doesNotMatch(triggers, /schedule:/);
  assert.doesNotMatch(triggers, /branches:/);

  assert.match(scale, /cancel-in-progress: false/);

  const javascriptStart = scale.indexOf('\n  javascript-exact-scale:\n');
  const rustStart = scale.indexOf('\n  rust-exact-scale:\n');
  const comparisonStart = scale.indexOf('\n  compare-exact-scale:\n');
  assert.ok(javascriptStart > 0 && rustStart > javascriptStart && comparisonStart > rustStart);
  const javascript = scale.slice(javascriptStart, rustStart);
  const rust = scale.slice(rustStart, comparisonStart);
  const comparison = scale.slice(comparisonStart);

  assert.match(
    javascript,
    /\n  javascript-exact-scale:\n    if: \$\{\{ github\.event_name == 'push' \|\| inputs\.confirm_exact_scale == true \}\}/
  );
  assert.match(
    rust,
    /\n  rust-exact-scale:\n    if: \$\{\{ github\.event_name == 'push' \|\| inputs\.confirm_exact_scale == true \}\}/
  );
  assert.doesNotMatch(javascript, /\n    needs:/);
  assert.doesNotMatch(rust, /\n    needs:/);
  assert.match(javascript, /timeout-minutes: 120/);
  assert.match(rust, /timeout-minutes: 120/);
  assert.match(javascript, /node core\/object-model\/js\/scripts\/run-scale\.mjs/);
  assert.doesNotMatch(javascript, /release_scale_tree_and_one_tib_manifest/);
  assert.doesNotMatch(javascript, /rust-toolchain/);
  assert.doesNotMatch(javascript, /npm ci/);
  assert.match(rust, /release_scale_tree_and_one_tib_manifest/);
  assert.doesNotMatch(rust, /core\/object-model\/js\/scripts\/run-scale\.mjs/);
  assert.doesNotMatch(rust, /setup-node/);
  assert.match(
    rust,
    /OGVCS_SCALE_REPORT_PATH: \$\{\{ github\.workspace \}\}\/artifacts\/rust-scale\.json/
  );
  assert.match(javascript, /name: object-model-scale-javascript-Linux/);
  assert.match(rust, /name: object-model-scale-rust-Linux/);

  assert.match(
    comparison,
    /\n  compare-exact-scale:\n(?:    .+\n)+?    needs:\n      - javascript-exact-scale\n      - rust-exact-scale\n/
  );
  assert.match(comparison, /name: object-model-scale-javascript-Linux/);
  assert.match(comparison, /name: object-model-scale-rust-Linux/);
  assert.match(comparison, /tools\/compare-object-model-scale\.mjs/);
  assert.match(comparison, /name: object-model-scale-Linux/);
  assert.doesNotMatch(comparison, /release_scale_tree_and_one_tib_manifest/);
  assert.doesNotMatch(comparison, /core\/object-model\/js\/scripts\/run-scale\.mjs/);
});

test('completed OGVCS-002 evidence is durable and lifecycle-consistent', async (t) => {
  const [completionSource, evidenceReadme, prd, formatReadme, encoding] = await Promise.all([
    readFile(completionEvidencePath, 'utf8'),
    readFile(evidenceReadmePath, 'utf8'),
    readFile(completedPrdPath, 'utf8'),
    readFile(formatReadmePath, 'utf8'),
    readFile(encodingPath, 'utf8')
  ]);
  const completion = JSON.parse(completionSource);
  assert.equal(completion.status, 'completed');
  assert.equal(completion.remainingCompletionGates.length, 0);
  assert.equal(completion.ordinaryConformance.conclusion, 'success');
  assert.deepEqual(completion.ordinaryConformance.conformance.comparisonReport, {
    filename: 'object-model-conformance-comparison.json',
    sizeBytes: 1323,
    sha256: '6a6ad6a10149181acff509351bc9b39d20f468ebce2ad38a43a91a9bae74fdc3'
  });
  assert.equal(completion.exactScale.conclusion, 'success');
  assert.equal(completion.exactScale.result, 'byte-identical-and-bounded');
  assert.equal(
    completion.ordinaryConformance.runId,
    32719990180
  );
  assert.equal(completion.dependentProtocolConformance.runId, 32719990210);
  assert.equal(completion.dependentProtocolConformance.conclusion, 'success');
  assert.equal(
    completion.dependentProtocolConformance.sourceRevision,
    completion.testedBoundaries.ratifiedPackageSourceRevision
  );
  assert.equal(completion.exactScale.runId, 32714126083);

  const reports = new Map();
  const reportBytes = new Map();
  for (const expected of completion.exactScale.durableReports) {
    const bytes = await readFile(new URL(expected.path, completionEvidencePath));
    assert.equal(bytes.length, expected.bytes, `${expected.path}: byte length drifted`);
    assert.equal(
      createHash('sha256').update(bytes).digest('hex'),
      expected.sha256,
      `${expected.path}: SHA-256 drifted`
    );
    reports.set(expected.path, JSON.parse(bytes));
    reportBytes.set(expected.path, bytes);
  }

  const javascript = reports.get('exact-scale-javascript-2026-08-24.json');
  const rust = reports.get('exact-scale-rust-2026-08-24.json');
  const comparison = reports.get('exact-scale-comparison-2026-08-24.json');
  const replayDirectory = await mkdtemp(join(tmpdir(), 'ogvcs-002-exact-replay-'));
  t.after(() => rm(replayDirectory, { recursive: true, force: true }));
  const replayPath = join(replayDirectory, 'comparison.json');
  const replay = spawnSync(process.execPath, [
    fileURLToPath(scaleComparatorPath),
    '--javascript', fileURLToPath(new URL('exact-scale-javascript-2026-08-24.json', completionEvidencePath)),
    '--rust', fileURLToPath(new URL('exact-scale-rust-2026-08-24.json', completionEvidencePath)),
    '--output', replayPath
  ], { encoding: 'utf8' });
  assert.equal(replay.status, 0, replay.stderr);
  assert.deepEqual(
    await readFile(replayPath),
    reportBytes.get('exact-scale-comparison-2026-08-24.json')
  );
  assert.equal(
    completion.ordinaryConformance.sourceRevision,
    completion.testedBoundaries.ratifiedPackageSourceRevision
  );
  assert.equal(
    completion.exactScale.sourceRevision,
    completion.testedBoundaries.exactImplementationSourceRevision
  );
  assert.deepEqual(completion.testedBoundaries.ratificationDeltaPaths, [
    'docs/evidence/OGVCS-002/exact-scale-comparison-2026-08-24.json',
    'docs/evidence/OGVCS-002/exact-scale-javascript-2026-08-24.json',
    'docs/evidence/OGVCS-002/exact-scale-rust-2026-08-24.json',
    'spec/repository-format/v1/README.md',
    'spec/repository-format/v1/encoding.md'
  ]);
  assert.deepEqual(completion.ordinaryConformance.packedConformance, {
    result: 'identical',
    comparisonReport: {
      filename: 'packed-conformance-comparison.json',
      sizeBytes: 1738,
      sha256: '3f6cf8f50b36ee196b561bac4e7d4b435097b4f3592c9128c42d74ab7137648d'
    },
    artifacts: [
      {
        filename: 'opengamevcs-fixture-generator-1.0.0.tgz',
        name: '@opengamevcs/fixture-generator',
        version: '1.0.0',
        sizeBytes: 144298,
        sha256: '3096bb6418a774e8f0757377e4b0453adae5e53ad8c37a2a51563d4c77634b93'
      },
      {
        filename: 'opengamevcs-object-model-0.1.0.tgz',
        name: '@opengamevcs/object-model',
        version: '0.1.0',
        sizeBytes: 193380,
        sha256: '009275ba22ced3fe973ee5b160ce088e25e0c2d6668068fc95e7a4174ec69f9a'
      },
      {
        filename: 'opengamevcs-repository-format-v1-0.1.0.tgz',
        name: '@opengamevcs/repository-format-v1',
        version: '0.1.0',
        sizeBytes: 874238,
        sha256: 'eaf2ad8e45e4cbac32a107606c6fb8d65b415b5aea1378202c2eefb081200d6a'
      },
      {
        filename: 'ogvcs-object-model-0.1.0.crate',
        name: 'ogvcs-object-model',
        version: '0.1.0',
        sizeBytes: 292410,
        sha256: '679880e40b6ed6d48e9eea61675520f365bc610eafb1b8c501afe652be8fd293'
      }
    ]
  });
  assert.equal(javascript.sourceRevision, completion.exactScale.sourceRevision);
  assert.equal(rust.sourceRevision, completion.exactScale.sourceRevision);
  assert.equal(comparison.sourceRevision, completion.exactScale.sourceRevision);
  assert.equal(javascript.exactV1Scale, true);
  assert.equal(rust.exactV1Scale, true);
  assert.equal(comparison.result, completion.exactScale.result);
  assert.equal(javascript.tree.entries, completion.exactScale.identity.treeEntries);
  assert.equal(rust.tree.entries, completion.exactScale.identity.treeEntries);
  assert.equal(
    javascript.manifest.logicalBytes,
    completion.exactScale.identity.manifestLogicalBytes
  );
  assert.equal(
    rust.manifest.logicalBytes,
    completion.exactScale.identity.manifestLogicalBytes
  );
  for (const report of [javascript, rust]) {
    assert.equal(report.tree.objectRef, completion.exactScale.identity.treeObjectRef);
    assert.equal(
      report.tree.payloadSha256Hex,
      completion.exactScale.identity.treePayloadSha256
    );
    assert.equal(report.manifest.objectRef, completion.exactScale.identity.manifestObjectRef);
    assert.equal(
      report.manifest.payloadSha256Hex,
      completion.exactScale.identity.manifestPayloadSha256
    );
    assert.equal(
      report.manifest.wholeFileDigestHex,
      completion.exactScale.identity.wholeFileDigestSha256
    );
    assert.ok(report.process.maxRssBytes > 0);
    assert.ok(report.process.maxRssBytes < completion.exactScale.resources.limitBytes);
  }
  assert.equal(javascript.manifest.verification.contentVerified, true);
  assert.equal(rust.manifest.contentVerified, true);
  assert.equal(rust.manifest.providerReads, completion.exactScale.performance.rustManifestProviderReads);
  assert.deepEqual(comparison.identity, {
    chunkObjectRef: javascript.manifest.chunkObjectRef,
    manifestObjectRef: completion.exactScale.identity.manifestObjectRef,
    manifestOutputBytes: javascript.manifest.outputBytes,
    manifestPayloadSha256Hex: completion.exactScale.identity.manifestPayloadSha256,
    rawChunkSha256Hex: javascript.manifest.rawChunkSha256Hex,
    treeObjectRef: completion.exactScale.identity.treeObjectRef,
    treeOutputBytes: javascript.tree.outputBytes,
    treePayloadSha256Hex: completion.exactScale.identity.treePayloadSha256,
    wholeFileDigestHex: completion.exactScale.identity.wholeFileDigestSha256
  });
  for (const value of Object.values(comparison.resources)) {
    assert.ok(value > 0);
    assert.ok(value < completion.exactScale.resources.limitBytes);
  }
  assert.equal(completion.futureMaintenance.pullRequestExactScale, false);
  assert.match(completion.futureMaintenance.exactScaleCadence, /monthly or major release/);

  assert.match(evidenceReadme, /\*\*Status:\*\* Completed;/);
  assert.match(evidenceReadme, /run 32714126083/);
  assert.doesNotMatch(evidenceReadme, /optimized-source recurrence and final publication remain open/);
  assert.match(prd, /^\*\*Status:\*\* Done$/m);
  assert.match(prd, /run 32714126083/);
  assert.match(formatReadme, /^\*\*Status:\*\* Ratified format-v1 contract$/m);
  assert.match(encoding, /^\*\*Status:\*\* Ratified format-v1 contract$/m);
});
