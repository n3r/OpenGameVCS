#!/usr/bin/env node

import { mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  comparePortableConformanceReports,
  readGitSourceEvidence,
  runPrivatePortableConformance,
} from '../src/internal/conformance-evidence.mjs';
import {
  buildLinuxConformanceReport,
  buildLinuxConformanceReportV2,
} from '../src/internal/linux-conformance-report.mjs';
import { canonicalJson, sha256 } from '../src/internal/reference-contract.mjs';
import { REFERENCE_SERVICE_HARD_KILL_BOUNDARIES } from '../src/internal/reference-service.mjs';

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../../..');
const historicalV1Path = 'docs/evidence/OGVCS-045/linux-reference-conformance-2026-09-02-run-33636956770.json';
const dispositions = Object.freeze({
  'after-acquisition-state': 'recovered-denied',
  'after-admission': 'recovered-denied',
  'after-committing-state': 'recovered-denied',
  'after-input-stage': 'recovered-denied',
  'after-output-collection': 'recovered-denied',
  'after-output-commit': 'recovered-denied',
  'after-result-commit': 'replayed-validated',
  'after-running-state': 'recovered-denied',
  'after-stage': 'recovered-denied',
  'after-validating-state': 'quarantined-nonterminal',
  'after-validation': 'recovered-denied',
  'after-worker': 'quarantined-nonterminal',
  'before-output-commit': 'recovered-denied',
});

const writeCanonical = (path, value) => writeFile(path, Buffer.from(`${canonicalJson(value)}\n`, 'utf8'), { flag: 'wx', mode: 0o600 });

const args = process.argv.slice(2);
if (args.length !== 4 || args[0] !== '--output-directory' || args[2] !== '--source-revision') {
  throw new Error('usage: node scripts/source-model-conformance.mjs --output-directory <directory> --source-revision <40-hex>');
}
if (Number.parseInt(process.versions.node.split('.')[0], 10) !== 24) throw new Error('source-model conformance requires Node 24');
const outputDirectory = resolve(args[1]);
const sourceRevision = args[3];
const source = await readGitSourceEvidence({ repositoryRoot, sourceRevision });
await mkdir(outputDirectory, { mode: 0o700 });

const portableReports = [];
for (const platform of ['linux', 'macos', 'windows']) {
  const report = await runPrivatePortableConformance({ platform, sourceFiles: source.sourceFiles, sourceRevision });
  portableReports.push(report);
  await writeCanonical(join(outputDirectory, `portable-${platform}-source-model.json`), report);
}
const comparison = comparePortableConformanceReports(portableReports);
await writeCanonical(join(outputDirectory, 'portable-source-model-comparison.json'), comparison);

const historicalPath = join(repositoryRoot, historicalV1Path);
const historicalDetails = await stat(historicalPath);
if (!historicalDetails.isFile() || historicalDetails.size < 1 || historicalDetails.size > 8 * 1024 * 1024) throw new Error('historical Linux v1 evidence is unavailable or unbounded');
const historicalBytes = await readFile(historicalPath);
const historicalSource = JSON.parse(historicalBytes.toString('utf8'));
const historicalV1 = buildLinuxConformanceReport({
  cases: historicalSource.cases,
  failure: historicalSource.failure,
  outcome: historicalSource.outcome,
  runtimeDigest: historicalSource.runtimeDigest,
  seccompProfileSha256: historicalSource.seccompProfileSha256,
});
if (historicalV1.schemaVersion !== historicalSource.schemaVersion
  || canonicalJson(historicalV1) !== canonicalJson(historicalSource)) throw new Error('historical Linux v1 evidence differs from its closed schema');
const syntheticV2 = buildLinuxConformanceReportV2({
  cases: historicalV1.cases,
  controls: {
    architecture: 'amd64',
    availableControllers: ['cpu', 'memory', 'pids'],
    cgroupNamespace: true,
    cgroupVersion: 2,
    operatingSystem: 'linux',
    rootless: false,
    runtimeBinaryBinding: 'unproven',
    runtimeCommit: 'unobserved',
    runtimeName: 'runc',
    runtimePathKind: 'relative-name',
    runtimeVersion: 'unobserved',
    seccomp: true,
  },
  failure: historicalV1.failure,
  outcome: historicalV1.outcome,
  runtimeDigest: historicalV1.runtimeDigest,
  seccompProfileSha256: historicalV1.seccompProfileSha256,
  sourceFiles: source.sourceFiles,
  sourceRevision,
});
const linuxFixture = Object.freeze({
  claimBoundary: Object.freeze({
    completeControllerObservation: false,
    dockerExecution: false,
    hostedRetention: false,
    liveRuntimeObservation: false,
    publicAdmission: false,
  }),
  evidenceKind: 'synthetic-source-only-schema-fixture',
  historicalV1: Object.freeze({ path: historicalV1Path, sha256: sha256(historicalBytes) }),
  report: syntheticV2,
  schemaVersion: 'ogvcs.untrusted-sandbox/linux-conformance-v2-schema-fixture/v1',
});
await writeCanonical(join(outputDirectory, 'linux-v2-source-only-schema-fixture.json'), linuxFixture);

const representedResources = new Set(['after-worker', 'after-validating-state']);
const outputBeforeRestart = new Set(['after-output-commit', 'after-result-commit']);
const killModel = Object.freeze({
  cases: Object.freeze(REFERENCE_SERVICE_HARD_KILL_BOUNDARIES.map((boundary) => Object.freeze({
    automaticDaemonCleanup: false,
    boundary,
    destructiveCalls: 0,
    expectedDisposition: dispositions[boundary],
    expectedOutputBeforeRestart: outputBeforeRestart.has(boundary),
    representedResource: representedResources.has(boundary),
  }))),
  claimBoundary: Object.freeze({
    childExecution: false,
    dockerExecution: false,
    hostedRetention: false,
    publicAdmission: false,
  }),
  evidenceKind: 'non-executed-source-model',
  outcome: 'not-executed',
  retentionStatus: 'not-hosted',
  schemaVersion: 'ogvcs.untrusted-sandbox/kill-boundary-conformance-model/v1',
  ...source,
});
await writeCanonical(join(outputDirectory, 'kill-boundary-source-model.json'), killModel);

process.stdout.write(`${canonicalJson({ files: 6, outputDirectory, retentionStatus: 'not-hosted', sourceRevision })}\n`);
