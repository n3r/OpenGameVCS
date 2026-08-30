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
  assert.deepEqual(completion.authority, {
    manifestFileSha256: MANIFEST,
    artifactSetSha256: 'ba59c8dc9db4c0678fc630357396d9981934ac065b0dd2c8bbbb5c82dccad6d7',
    schemaSetSha256: 'f186e1cfe4d8905b0fe36acfa641b3a97eed3f8bcb9d245c7a96055d9cd6f706',
    registrySetSha256: 'bbe8230b1a115b5c0862537d7dde6e97db61c283b552dad61d2020165b75d532',
    vectorSetSha256: '7ab9d07b3f88e94be05f3d48bcd0b8e7bfac79ade49dad3e87f3f1d859a501b7',
    thresholdSetSha256: '13a1cf5e4d20dadced0b04bdc3cc8b3d01a5c3b2a42ca04e163b08e147dac7ff',
    modelSha256: 'bdbd0f9c5d5573d8e9ee318cefc31bd8bc3a3d6fa239f8b0dbf49f9c0c8c2099',
    generatorSha256: '05d252d450785f628be40771db38ba25b8d22fe251c0b0014cf5a66dc1f93334',
    validatorSha256: '95c6a4353bf57cad1659aa4f2e6d305b3b0231fb6ccd9ca8196cb6030839188e',
    fixtureProfileSetSha256: '6b53f4274d8b2374224728d0cebd499e58ab990c4e6409fa5403bf8f38934b36',
    counts: {
      artifacts: 28,
      schemas: 17,
      registries: 8,
      scenarios: 35,
      tasks: 11,
      faultPoints: 12,
      thresholds: 8,
    },
  });
  assert.deepEqual(completion.predecessors, {
    repositoryManifestSha256: '2d0acb01a01b64c23d883d855d2802d939a8dc99622f2774de07af1c8af8d2b9',
    authorizationManifestSha256: '3fb4dd4a89eb914f93a589b013bda8afcf4744c0d27171ee5849ca3b7bf62447',
    authorizationRegistrySetSha256: '293f9ab0be023a9ded33326d04a8314080bda56e7c70dd18d0cca38b70bed9cc',
    pathManifestSha256: '2f343e1dac238da527fbd36160419ec6fb53b780ac7e33c01e11acabbdd4782b',
    pathRegistrySetSha256: 'bbabdd95d78cfe0dd9751ab67ccbd9dfa5565bf8c049468aea3129bec787bd42',
    protocolManifestSha256: 'bc343842291040b6b0c2c941b183863500c4d60a4618256ffc6e36a1d6afbe72',
    protocolRegistrySetSha256: '2a49361363cc16e743948fa3cc5e266cd1bc6e31b312cde15b5dab1ad7e5c5b0',
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
