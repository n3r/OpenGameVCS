import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const evidenceDirectory = new URL('../docs/evidence/OGVCS-004/', import.meta.url);
const runEvidencePath = new URL('github-actions-run-32831999325.json', evidenceDirectory);
const policyRunEvidencePath = new URL(
  'github-actions-run-32833243994.json',
  evidenceDirectory
);
const traceAuditPath = new URL('./path-filesystem-trace-audit.mjs', import.meta.url);
const evidenceReadmePath = new URL('README.md', evidenceDirectory);
const completedPrdPath = new URL(
  '../prd/done/OGVCS-004-cross-platform-path-filesystem-library.md',
  import.meta.url
);
const reviewPath = new URL(
  '../docs/reviews/OGVCS-004-critical-review.md',
  import.meta.url
);
const changelogPath = new URL('../docs/changelog/OGVCS-004.md', import.meta.url);
const adrPath = new URL(
  '../adr/0012-path-and-workspace-filesystem-contract-v1.md',
  import.meta.url
);
const roadmapPath = new URL('../prd/ROADMAP.md', import.meta.url);
const workflowPath = new URL('../.github/workflows/path-filesystem.yml', import.meta.url);
const streamingPrdPath = new URL(
  '../prd/todo/OGVCS-046-bounded-staged-workspace-publication.md',
  import.meta.url
);
const streamingChangelogPath = new URL('../docs/changelog/OGVCS-046.md', import.meta.url);
const streamingEvidencePath = new URL('../docs/evidence/OGVCS-046/README.md', import.meta.url);
const streamingRunbookPath = new URL(
  '../docs/runbooks/OGVCS-046-read-before-write-rollback.md',
  import.meta.url
);

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

function canonicalJson(value) {
  if (
    value === null ||
    typeof value === 'boolean' ||
    typeof value === 'string' ||
    Number.isSafeInteger(value)
  ) {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(value).sort().map(
    (key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`
  ).join(',')}}`;
}

async function readBoundArtifact(expected) {
  const bytes = await readFile(new URL(expected.filename, evidenceDirectory));
  assert.equal(bytes.length, expected.sizeBytes, `${expected.filename}: byte length drifted`);
  assert.equal(sha256(bytes), expected.sha256, `${expected.filename}: SHA-256 drifted`);
  return { bytes, value: JSON.parse(bytes) };
}

test('completed OGVCS-004 hosted evidence is source-bound and internally consistent', async () => {
  const evidence = JSON.parse(await readFile(runEvidencePath));
  assert.equal(evidence.schema, 'ogvcs.path/hosted-validation-evidence/v1');
  assert.equal(evidence.status, 'completed');
  assert.equal(evidence.github.repository, 'n3r/OpenGameVCS');
  assert.equal(evidence.github.runId, 32831999325);
  assert.equal(
    evidence.github.sourceRevision,
    '4f8a5a0f836ef51b4ac56cab9d795d7f5515926d'
  );
  assert.equal(evidence.github.conclusion, 'success');
  assert.equal(evidence.github.jobs.length, 4);
  assert.ok(evidence.github.jobs.every(({ conclusion }) => conclusion === 'success'));
  assert.deepEqual(
    new Set(evidence.github.jobs.map(({ name }) => name)),
    new Set([
      'Packed conformance (macos-latest)',
      'Packed conformance (windows-latest)',
      'Packed conformance (ubuntu-latest)',
      'Compare Linux, macOS, and Windows results'
    ])
  );
  assert.equal(evidence.github.artifacts.length, 3);
  assert.deepEqual(
    new Set(evidence.github.artifacts.map(({ name }) => name)),
    new Set(['path-filesystem-Linux', 'path-filesystem-macOS', 'path-filesystem-Windows'])
  );
  for (const artifact of evidence.github.artifacts) {
    assert.match(artifact.githubArchiveDigest, /^sha256:[0-9a-f]{64}$/u);
    assert.ok(artifact.id > 0);
    assert.ok(artifact.sizeBytes > 0);
  }

  assert.deepEqual(evidence.contract, {
    version: '1.0.0',
    manifestSha256: '2f343e1dac238da527fbd36160419ec6fb53b780ac7e33c01e11acabbdd4782b',
    registrySetSha256: 'bbabdd95d78cfe0dd9751ab67ccbd9dfa5565bf8c049468aea3129bec787bd42',
    unicodeCaseFoldingSha256: '6f1f9c588eb4a5c718d9e8f93b782685e5c7fec872cf05e8e6878053599e09bb',
    resultsSha256: 'a21941590359b85c6a45cdab432bfec636c66b13d524746c0dadbaf97da41616',
    pureRows: 63,
    nativeRows: 15,
    totalRows: 78
  });

  const reports = [];
  for (const expected of evidence.packedConformance.reportArtifacts) {
    const { value: report } = await readBoundArtifact(expected);
    assert.equal(report.schemaVersion, 'ogvcs.path/conformance-report/v1');
    assert.equal(report.contractVersion, evidence.contract.version);
    assert.equal(report.manifestSha256, evidence.contract.manifestSha256);
    assert.equal(report.registrySetSha256, evidence.contract.registrySetSha256);
    assert.equal(report.unicodeCaseFoldingSha256, evidence.contract.unicodeCaseFoldingSha256);
    assert.equal(report.resultsSha256, evidence.contract.resultsSha256);
    assert.deepEqual(
      { total: report.total, passed: report.passed, failed: report.failed },
      { total: 78, passed: 78, failed: 0 }
    );
    assert.equal(report.results.length, 78);
    assert.equal(
      report.results.filter(({ category }) => category !== 'native-filesystem').length,
      evidence.contract.pureRows
    );
    assert.equal(
      sha256(Buffer.from(canonicalJson(report.results), 'utf8')),
      report.resultsSha256
    );
    assert.ok(report.results.every(
      ({ passed, expectedSha256, actualSha256 }) =>
        passed === true && expectedSha256 === actualSha256
    ));
    reports.push(report);
  }
  assert.deepEqual(new Set(reports.map(({ platform }) => platform)), new Set([
    'linux',
    'macos',
    'windows'
  ]));
  assert.ok(reports.slice(1).every(
    ({ results }) => canonicalJson(results) === canonicalJson(reports[0].results)
  ));

  const packedEvidence = [];
  for (const expected of evidence.packedConformance.packedEvidenceArtifacts) {
    const { value: packed } = await readBoundArtifact(expected);
    assert.equal(packed.schemaVersion, 'ogvcs.path/packed-evidence/v1');
    assert.equal(packed.resultsSha256, evidence.contract.resultsSha256);
    const report = reports.find(({ platform }) => platform === packed.platform);
    assert.ok(report, `${packed.platform}: missing retained report`);
    assert.equal(
      packed.report.sha256,
      evidence.packedConformance.reportArtifacts.find(
        ({ platform }) => platform === packed.platform
      ).sha256
    );
    packedEvidence.push(packed);
  }

  const expectedPackages = evidence.packedConformance.packages.map(
    ({ filename, name, version, sha256: digest }) => ({ filename, name, version, sha256: digest })
  );
  for (const packed of packedEvidence) assert.deepEqual(packed.packages, expectedPackages);

  const { value: comparison } = await readBoundArtifact(
    evidence.packedConformance.comparison
  );
  assert.deepEqual(comparison, {
    schemaVersion: 'ogvcs.path/comparison/v1',
    reports: 3,
    platforms: ['linux', 'macos', 'windows'],
    contractVersion: evidence.contract.version,
    manifestSha256: evidence.contract.manifestSha256,
    registrySetSha256: evidence.contract.registrySetSha256,
    unicodeCaseFoldingSha256: evidence.contract.unicodeCaseFoldingSha256,
    resultsSha256: evidence.contract.resultsSha256,
    packages: expectedPackages.map(({ name, version, sha256: digest }) => ({
      name,
      version,
      sha256: digest
    })),
    total: 78,
    result: 'equal'
  });

  assert.deepEqual(evidence.exactScale, {
    applicable: false,
    reason: 'The million-entry tree and logical-1-TiB campaign belongs to completed OGVCS-002; OGVCS-004 has only bounded path/materialization acceptance rows.'
  });
});

test('retained Linux syscall trace independently proves outside-root confinement', async () => {
  const evidence = JSON.parse(await readFile(runEvidencePath));
  const expected = evidence.packedConformance.syscallTrace;
  const trace = await readFile(new URL(expected.filename, evidenceDirectory));
  assert.equal(trace.length, expected.sizeBytes);
  assert.equal(sha256(trace), expected.sha256);
  assert.equal((trace.toString('utf8').match(/\n/gu) ?? []).length, expected.lines);

  const audit = await readBoundArtifact(expected.audit);
  assert.deepEqual(audit.value, {
    schemaVersion: 'ogvcs.path/filesystem-trace-audit/v1',
    bytes: expected.sizeBytes,
    lines: expected.lines,
    sha256: expected.sha256,
    outsideReferences: 0
  });

  const replay = spawnSync(process.execPath, [
    fileURLToPath(traceAuditPath),
    '--trace', fileURLToPath(new URL(expected.filename, evidenceDirectory)),
    '--workspace', '/home/runner/work/_temp/ogvcs-path-trace-workspace',
    '--outside', '/home/runner/work/_temp/ogvcs-path-trace-outside'
  ], { encoding: 'utf8' });
  assert.equal(replay.status, 0, replay.stderr);
  assert.deepEqual(JSON.parse(replay.stdout), audit.value);

  const fixture = await readBoundArtifact(expected.fixture);
  assert.deepEqual(fixture.value, {
    schemaVersion: 'ogvcs.path/trace-fixture-result/v1',
    denied: true,
    symlinkAncestor: 'UNSAFE_TARGET',
    targetRace: 'TARGET_CHANGED',
    ancestorRace: 'TARGET_CHANGED'
  });
});

test('evidence-policy validation is bound to the retained implementation proof', async () => {
  const policyRun = JSON.parse(await readFile(policyRunEvidencePath));
  assert.equal(policyRun.schema, 'ogvcs.path/evidence-policy-validation/v1');
  assert.equal(policyRun.status, 'completed');
  assert.deepEqual(policyRun.implementationEvidence, {
    sourceRevision: '4f8a5a0f836ef51b4ac56cab9d795d7f5515926d',
    runId: 32831999325,
    machineRecord: 'github-actions-run-32831999325.json'
  });
  assert.equal(policyRun.github.runId, 32833243994);
  assert.equal(
    policyRun.github.sourceRevision,
    '94f68c80f9166ef3deb7aa65b9cb268453af714f'
  );
  assert.equal(policyRun.github.conclusion, 'success');
  assert.equal(policyRun.github.jobs.length, 4);
  assert.ok(policyRun.github.jobs.every(({ conclusion }) => conclusion === 'success'));
  assert.equal(policyRun.github.artifacts.length, 3);
  assert.ok(policyRun.github.artifacts.every(
    ({ id, sizeBytes, githubArchiveDigest }) =>
      id > 0 && sizeBytes > 0 && /^sha256:[0-9a-f]{64}$/u.test(githubArchiveDigest)
  ));
  assert.equal(policyRun.validatedClaims.length, 5);
});

test('completed OGVCS-004 lifecycle claims stay aligned with durable evidence', async () => {
  const [evidenceReadme, prd, review, changelog, adr, roadmap] = await Promise.all([
    readFile(evidenceReadmePath, 'utf8'),
    readFile(completedPrdPath, 'utf8'),
    readFile(reviewPath, 'utf8'),
    readFile(changelogPath, 'utf8'),
    readFile(adrPath, 'utf8'),
    readFile(roadmapPath, 'utf8')
  ]);
  assert.match(evidenceReadme, /\*\*Status:\*\* Completed/u);
  assert.match(evidenceReadme, /actions\/runs\/32831999325/u);
  assert.match(evidenceReadme, /actions\/runs\/32833243994/u);
  assert.match(evidenceReadme, /63 pure cross-platform rows|Pure cross-platform rows \| 63/u);
  assert.match(evidenceReadme, /Bounded native filesystem rows \| 15/u);
  assert.doesNotMatch(evidenceReadme, /Deferred roadmap completion/u);

  assert.match(prd, /\*\*Status:\*\* Done/u);
  for (const number of [1, 2, 3, 4, 5]) {
    const id = `OGVCS-004-AC-${String(number).padStart(2, '0')}`;
    assert.match(prd, new RegExp(`^- ${id}: .*\\[[^\\]]+\\]\\([^)]+\\)`, 'mu'));
  }
  assert.match(review, /\*\*Current verdict:\*\* Acceptance-ready; no live P0, P1, or P2/u);
  assert.match(changelog, /### Hosted completion evidence/u);
  assert.match(adr, /\*\*Status:\*\* Accepted/u);
  assert.match(
    roadmap,
    /\[Cross-platform path and workspace filesystem library\]\(done\/OGVCS-004-cross-platform-path-filesystem-library\.md\)/u
  );
});

test('in-development OGVCS-046 validation is routed without claiming hosted success', async () => {
  const [workflow, prd, changelog, evidence, runbook] = await Promise.all([
    readFile(workflowPath, 'utf8'),
    readFile(streamingPrdPath, 'utf8'),
    readFile(streamingChangelogPath, 'utf8'),
    readFile(streamingEvidencePath, 'utf8'),
    readFile(streamingRunbookPath, 'utf8')
  ]);

  for (const path of [
    'docs/changelog/OGVCS-046.md',
    'docs/evidence/OGVCS-046/**',
    'docs/runbooks/OGVCS-046-*.md',
    'prd/todo/OGVCS-046-*.md'
  ]) {
    assert.equal(
      workflow.match(new RegExp(path.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&'), 'gu'))?.length,
      2,
      `${path} must trigger both pull-request and push validation`
    );
  }
  assert.match(workflow, /- "ogvcs-046\/\*\*"/u);
  assert.match(workflow, /- "ogvcs046-\*"/u);
  assert.equal(workflow.match(/node-version: 22/gu)?.length, 2);
  assert.equal(
    workflow.match(/actions\/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1/gu)?.length,
    2
  );
  assert.match(
    workflow,
    /actions\/setup-node@820762786026740c76f36085b0efc47a31fe5020/u
  );
  assert.match(
    workflow,
    /actions\/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a/u
  );
  assert.match(
    workflow,
    /actions\/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c/u
  );

  assert.match(prd, /\*\*Status:\*\* In development/u);
  assert.match(changelog, /Hosted Linux, macOS, and Windows validation remains pending/u);
  assert.match(evidence, /\*\*Status:\*\* Pending hosted validation/u);
  assert.match(evidence, /79 total rows/u);
  assert.doesNotMatch(evidence, /actions\/runs\/\d+/u);
  assert.match(runbook, /readers and recovery tooling before enabling writers/u);
  assert.match(runbook, /all `write-stream` remnants/u);
});
