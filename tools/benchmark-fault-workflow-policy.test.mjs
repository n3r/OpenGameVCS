import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, stat } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const EVIDENCE = join(ROOT, 'docs/evidence/OGVCS-005');
const COMPLETION = join(EVIDENCE, 'completion-2026-08-25.json');
const SOURCE = '2cd9b767349be1ed7f5bd9ffae87333fc3d9e9ad';
const MANIFEST = 'e8e1396ad31407d16b269258be2f55909ed7fed6ca8e7d14af52582db15d6612';
const PACKAGE_SET = '49f67a2f0de0a1fc96ff628befa3067252a3b533ea43b84b8fb2b954dbb781ac';
const SEMANTIC_RESULTS = 'abfc5fcd5e2edefa58b2ec1684fa4637689c9f547c0985b7c82dc40f8a63ce66';

function canonical(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string' || Number.isSafeInteger(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
}

function digest(value) {
  return createHash('sha256').update(Buffer.isBuffer(value) || typeof value === 'string' ? value : canonical(value)).digest('hex');
}

function domainDigest(value, domain) {
  return createHash('sha256').update(domain, 'utf8').update(Buffer.from([0])).update(canonical(value), 'utf8').digest('hex');
}

async function json(path) {
  return JSON.parse(await readFile(path, 'utf8'));
}

test('OGVCS-005 completion record authenticates durable hosted evidence', async () => {
  const completion = await json(COMPLETION);
  assert.equal(completion.schemaVersion, 'ogvcs.benchmark/completion-evidence/v1');
  assert.equal(completion.status, 'completed');
  assert.equal(completion.sourceRevision, SOURCE);
  assert.deepEqual(completion.remainingGates, []);
  assert.equal(completion.authority.manifestFileSha256, MANIFEST);
  const manifestBytes = await readFile(join(ROOT, 'spec/benchmark-fault/v1/manifest.json'));
  const manifest = JSON.parse(manifestBytes);
  assert.equal(digest(manifestBytes), MANIFEST);
  assert.deepEqual(completion.authority, {
    manifestFileSha256: MANIFEST,
    artifactSetSha256: manifest.artifactSetSha256,
    schemaSetSha256: manifest.schemaSetSha256,
    registrySetSha256: manifest.registrySetSha256,
    vectorSetSha256: manifest.vectorSetSha256,
    thresholdSetSha256: manifest.thresholdSetSha256,
    modelSha256: manifest.generatedBy.modelSha256,
    generatorSha256: manifest.generatedBy.generatorSha256,
    validatorSha256: digest(await readFile(join(ROOT, 'spec/benchmark-fault/v1/validate-spec.mjs'))),
    fixtureProfileSetSha256: manifest.predecessorPins.fixtures.profileSetSha256,
    counts: {
      artifacts: manifest.counts.artifacts,
      schemas: manifest.counts.schemas,
      registries: manifest.counts.registries,
      scenarios: manifest.counts.scenarios,
      tasks: manifest.counts.tasks,
      faultPoints: manifest.counts.faultPoints,
      thresholds: manifest.counts.thresholds,
    },
  });
  assert.deepEqual(completion.predecessors, {
    repositoryManifestSha256: manifest.predecessorPins.repository.manifestSha256,
    authorizationManifestSha256: manifest.predecessorPins.authorization.manifestSha256,
    authorizationRegistrySetSha256: manifest.predecessorPins.authorization.registrySetSha256,
    pathManifestSha256: manifest.predecessorPins.path.manifestSha256,
    pathRegistrySetSha256: manifest.predecessorPins.path.registrySetSha256,
    protocolManifestSha256: manifest.predecessorPins.protocol.manifestSha256,
    protocolRegistrySetSha256: manifest.predecessorPins.protocol.registrySetSha256,
  });
  assert.equal(completion.hosted.runId, 32850158064);
  assert.equal(completion.hosted.sourceRevision, SOURCE);
  assert.equal(completion.hosted.conclusion, 'success');
  assert.equal(completion.hosted.packageSetSha256, PACKAGE_SET);
  assert.equal(completion.hosted.semanticResultsSha256, SEMANTIC_RESULTS);
  assert.equal(completion.exactScale.executedForOgvcs005, false);
  assert.equal(completion.exactScale.predecessor.prd, 'OGVCS-002');
  assert.equal(completion.exactScale.predecessor.status, 'completed');

  const run = await json(join(EVIDENCE, completion.hosted.record));
  assert.equal(run.runId, completion.hosted.runId);
  assert.equal(run.sourceRevision, SOURCE);
  assert.equal(run.conclusion, 'success');
  assert.equal(run.jobs.filter(({ conclusion }) => conclusion === 'success').length, 5);
  assert.deepEqual(run.jobs.filter(({ conclusion }) => conclusion === 'success').map(({ id, name }) => ({ id, name })), [
    { id: 97808935806, name: 'Packed bounded conformance (ubuntu-latest)' },
    { id: 97808936049, name: 'Packed bounded conformance (windows-latest)' },
    { id: 97808936129, name: 'Packed bounded conformance (macos-latest)' },
    { id: 97808936123, name: 'Validate complete release-matrix scheduling' },
    { id: 97809293953, name: 'Compare Linux, macOS, and Windows semantic results' },
  ]);
  assert.equal(run.artifacts.length, 4);
  assert.deepEqual(run.artifacts.map(({ id }) => id), [9563951754, 9563942358, 9563921067, 9563920681]);
  assert.equal(run.comparison.comparisonSha256, completion.hosted.comparisonSha256);

  const retained = new Map();
  for (const expected of completion.retainedFiles) {
    const path = join(EVIDENCE, expected.path);
    const bytes = await readFile(path);
    const metadata = await stat(path);
    assert.equal(metadata.isFile(), true, expected.path);
    assert.equal(bytes.length, expected.sizeBytes, expected.path);
    assert.equal(digest(bytes), expected.sha256, expected.path);
    retained.set(expected.path, JSON.parse(bytes));
  }
  assert.equal(retained.size, 8);

  const platforms = ['linux', 'macos', 'windows'];
  const completionPackages = completion.packages.archives.map(({ name, version, sha256 }) => ({ name, version, sha256 }));
  for (const platform of platforms) {
    const envelope = retained.get(`packed-evidence-${platform}-2026-08-25.json`);
    const report = retained.get(`retained-report-${platform}-2026-08-25.json`);
    const { evidenceSha256, ...evidenceBody } = envelope;
    const { reportSha256, ...reportBody } = report;
    assert.equal(digest(evidenceBody), evidenceSha256);
    assert.equal(domainDigest(reportBody, 'ogvcs.benchmark/retained-report/v1'), reportSha256);
    assert.equal(envelope.contractManifestSha256, MANIFEST);
    assert.equal(envelope.packageSetSha256, PACKAGE_SET);
    assert.equal(envelope.semanticResultsSha256, SEMANTIC_RESULTS);
    assert.equal(envelope.exactScaleExecuted, false);
    assert.equal(envelope.report.sha256, completion.retainedFiles.find(({ path }) => path === `retained-report-${platform}-2026-08-25.json`).sha256);
    assert.equal(envelope.report.reportSha256, report.reportSha256);
    assert.equal(report.overallStatus, 'passed');
    assert.equal(report.results.conformanceFailed, 0);
    assert.equal(report.results.faultFailures, 0);
    assert.equal(report.results.brokenMisses, 0);
    assert.equal(report.results.securityMisses, 0);
    assert.deepEqual(envelope.packages.map(({ name, version, sha256 }) => ({ name, version, sha256 })), completionPackages);
  }
  assert.equal(completion.packages.packageSetSha256, PACKAGE_SET);
  assert.equal(completion.packages.count, completionPackages.length);
});

test('OGVCS-005 retained comparison is independently derived from three envelopes', async () => {
  const rows = await Promise.all(['linux', 'macos', 'windows'].map((platform) => json(join(EVIDENCE, `packed-evidence-${platform}-2026-08-25.json`))));
  const body = {
    schemaVersion: 'ogvcs.benchmark/cross-platform-comparison/v1',
    reports: rows.length,
    platforms: rows.map(({ platform }) => `${platform.os}/${platform.architecture}`).sort(),
    contractManifestSha256: rows[0].contractManifestSha256,
    profile: rows[0].profile,
    semanticResultsSha256: rows[0].semanticResultsSha256,
    packageSetSha256: rows[0].packageSetSha256,
    matched: true,
  };
  for (const field of ['contractManifestSha256', 'profile', 'semanticResultsSha256', 'packageSetSha256']) {
    assert.equal(new Set(rows.map((row) => row[field])).size, 1, field);
  }
  assert.equal(new Set(body.platforms).size, 3);
  const derived = `${canonical({ ...body, comparisonSha256: digest(body) })}\n`;
  const retained = await readFile(join(EVIDENCE, 'cross-platform-comparison-2026-08-25.json'), 'utf8');
  assert.equal(derived, retained);
});

test('OGVCS-005 lifecycle documents bind current source, run, authority, and scale policy', async () => {
  const paths = [
    'docs/evidence/OGVCS-005/README.md',
    'docs/reviews/OGVCS-005-critical-review.md',
    'docs/changelog/OGVCS-005.md',
    'prd/done/OGVCS-005-benchmark-and-fault-harness.md',
  ];
  for (const path of paths) {
    const text = await readFile(join(ROOT, path), 'utf8');
    assert.match(text, /2cd9b76/u, path);
    assert.match(text, /32850158064/u, path);
    assert.match(text, /1\.0\.0-rc\.1/u, path);
    assert.doesNotMatch(text, /32441625231|11c3038d6456e690|predecessors? (?:remain|pending)|exact-scale cases? (?:remain|pending)/iu, path);
  }
  const prd = await readFile(join(ROOT, 'prd/done/OGVCS-005-benchmark-and-fault-harness.md'), 'utf8');
  assert.match(prd, /^\*\*Status:\*\* Done$/mu);
  for (const label of ['Implementation changes', 'Test and benchmark results', 'Security/reliability review', 'Documentation/runbooks', 'Rollout result']) {
    assert.match(prd, new RegExp(`^- ${label}: .*\\[[^\\]]+\\]\\([^)]+\\)`, 'mu'));
  }
  for (let index = 1; index <= 7; index += 1) {
    const id = `OGVCS-005-AC-${String(index).padStart(2, '0')}`;
    assert.match(prd, new RegExp(`^- ${id}: .*\\[[^\\]]+\\]\\([^)]+\\)`, 'mu'));
  }
  const roadmap = await readFile(join(ROOT, 'prd/ROADMAP.md'), 'utf8');
  assert.match(roadmap, /done\/OGVCS-005-benchmark-and-fault-harness\.md/u);
  assert.doesNotMatch(roadmap, /todo\/OGVCS-005-benchmark-and-fault-harness\.md/u);
  const doneIndex = await readFile(join(ROOT, 'prd/done/README.md'), 'utf8');
  assert.match(doneIndex, /OGVCS-005-benchmark-and-fault-harness\.md/u);
});
