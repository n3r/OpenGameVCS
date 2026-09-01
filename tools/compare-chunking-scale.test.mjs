import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cp, lstat, mkdtemp, readFile, rm, unlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';

import { canonicalDigest, canonicalJson } from '../foundation/benchmark-fault-harness/src/index.mjs';
import {
  buildChunkingScaleEvidenceBundle,
  writeChunkingScaleEvidenceBundle,
} from './chunking-scale-evidence-bundle.mjs';
import {
  SCALE_BOUNDS,
  SCALE_ROOT,
  implementationAuthority,
  parseScaleReportText,
  sha256Bytes,
} from './chunking-scale-evidence-common.mjs';
import { runRawWorkflowPublicationForTest } from './compare-chunking-scale.mjs';

const REVISION = '0123456789abcdef0123456789abcdef01234567';
const SOURCE = Object.freeze({
  schemaVersion: 'ogvcs.chunking-manifest/scale-source-repeated-lcg-v1',
  logicalBytes: '107374182400',
  patternBytes: 8_388_608,
  repetitions: 12_800,
  patternSha256: 'b4798e6f4c78cbeb0b69d6a83b60dfb1bb68196f8c7913dec1bf1bc6fa3921a4',
  seed: 1_330_075_203,
  multiplier: 1_664_525,
  increment: 1_013_904_223,
  outputByte: 'state-bits-31-through-24-after-step',
});
const BOUNDS = SCALE_BOUNDS;
const RESULT = Object.freeze({
  class: 'cdc-1m',
  logicalBytes: '107374182400',
  chunkCount: 102_400,
  totalChunkBytes: '107374182400',
  minimumChunkBytes: 262_144,
  maximumChunkBytes: 2_097_152,
  wholeFileSha256: 'a'.repeat(64),
  manifestObjectId: `ogvcs:v1:content-manifest:sha256:${'b'.repeat(64)}`,
  manifestSha256: 'c'.repeat(64),
  manifestBytes: 5_120_047,
  boundaryTranscriptSha256: 'd'.repeat(64),
});
const PUBLISHER = Object.freeze({ os: 'linux', architecture: 'x64', nodeVersion: 'v24.9.0' });

function digest(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function report(implementation) {
  return {
    schemaVersion: 'ogvcs.chunking-manifest/scale-report/v1',
    implementation,
    profile: 'chunking.opengamevcs/gear-fastcdc-1m@1',
    sourceRevision: REVISION,
    exactScaleExecuted: true,
    runtime: {
      os: 'linux',
      architecture: 'x64',
      version: implementation === 'javascript' ? 'v24.9.0' : '1.82.0',
    },
    source: structuredClone(SOURCE),
    result: structuredClone(RESULT),
    resources: {
      wallTimeMilliseconds: 2_000_000,
      cpuMicroseconds: 1_500_000_000,
      cpuSource: implementationAuthority(implementation).cpuSource,
      diskReadBytes: 0,
      diskWriteBytes: 8_388_608,
      ioSource: 'linux:/proc/self/io:read_bytes+write_bytes',
      processWriteBytes: 16_777_216,
      processWriteSource: 'linux:/proc/self/io:wchar',
      measurementScope: 'source-pattern-generation-through-scratch-cleanup-before-report-publication',
      throughputBytesPerSecond: 53_687_091,
      peakRssBytes: 201_326_592,
      maxRssSource: implementationAuthority(implementation).maxRssSource,
      patternBufferBytes: 8_388_608,
      scalarWorkingMemoryBytes: 4_259_840,
      ledgerRecords: RESULT.chunkCount,
      ledgerPeakMemoryBytes: 1_048_560,
      ledgerPeakScratchBytes: 50_331_648,
      ledgerSpilled: true,
      scratchArtifactsAfter: 0,
    },
    bounds: structuredClone(BOUNDS),
    overallStatus: 'passed',
  };
}

const baselinePromises = new Map();

async function exactPublication(implementation, record) {
  return buildChunkingScaleEvidenceBundle({
    implementation,
    reportRecord: record,
    publisherEnvironmentForTest: { ...PUBLISHER, architecture: record.report.runtime.architecture },
  });
}

async function baselinePublication(implementation) {
  if (!baselinePromises.has(implementation)) {
    const text = `${JSON.stringify(report(implementation), null, 2)}\n`;
    baselinePromises.set(implementation, exactPublication(implementation, parseScaleReportText(text, implementation)));
  }
  return baselinePromises.get(implementation);
}

function artifact(path, text) {
  const bytes = Buffer.from(text);
  return { path, bytes: bytes.byteLength, sha256: sha256Bytes(bytes), mediaType: 'application/json' };
}

function rebuildPublication(baseline, reportText, mutateProjection) {
  const projection = structuredClone(baseline.projection);
  mutateProjection?.(projection);
  const projectionText = `${canonicalJson(projection)}\n`;
  const artifacts = [artifact('projection.json', projectionText), artifact('report.json', reportText)];
  const manifest = {
    ...baseline.manifest,
    artifacts,
    bundleDigest: canonicalDigest(artifacts, 'ogvcs.chunking-manifest/exact-scale-publication/v1'),
  };
  return Object.freeze({ ...baseline, manifest, manifestText: `${canonicalJson(manifest)}\n`, projection, projectionText, reportText });
}

async function publicationForText(implementation, text, mutateProjection) {
  let record;
  try { record = parseScaleReportText(text, implementation); } catch {}
  if (record && mutateProjection === undefined) return exactPublication(implementation, record);
  const baseline = await baselinePublication(implementation);
  return rebuildPublication(baseline, text, mutateProjection);
}

function internalArguments(args) {
  const values = {};
  for (let index = 0; index < args.length; index += 2) values[args[index]] = args[index + 1];
  return { javascript: values['--javascript'], rust: values['--rust'], output: values['--output'] };
}

function workflowPublicationPaths(output) {
  const stem = output.endsWith('.json') ? output.slice(0, -'.json'.length) : output;
  return {
    bundlePaths: {
      javascript: `${stem}.javascript.bundle`,
      rust: `${stem}.rust.bundle`,
    },
    publicationPaths: {
      javascript: `${stem}.javascript.publication.json`,
      rust: `${stem}.rust.publication.json`,
    },
    validationPaths: {
      javascript: `${stem}.javascript.validation.json`,
      rust: `${stem}.rust.validation.json`,
    },
  };
}

function invokeComparator(args) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(process.execPath, ['tools/compare-chunking-scale.mjs', ...args], {
      cwd: SCALE_ROOT,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const stdout = [];
    const stderr = [];
    child.stdout.on('data', (chunk) => stdout.push(chunk));
    child.stderr.on('data', (chunk) => stderr.push(chunk));
    child.once('error', reject);
    child.once('close', (code) => resolvePromise({
      code,
      stdout: Buffer.concat(stdout).toString('utf8'),
      stderr: Buffer.concat(stderr).toString('utf8'),
    }));
  });
}

async function run(args, options = {}) {
  const paths = internalArguments(args);
  if (options.mutateJavascriptProjection === undefined && options.mutateRustProjection === undefined) {
    const compared = await invokeComparator(args);
    return { ...compared, ...workflowPublicationPaths(paths.output) };
  }
  const [javascriptText, rustText] = await Promise.all([readFile(paths.javascript, 'utf8'), readFile(paths.rust, 'utf8')]);
  const bundlePaths = {
    javascript: join(dirname(paths.output), 'javascript-bundle'),
    rust: join(dirname(paths.output), 'rust-bundle'),
  };
  const [javascript, rust] = await Promise.all([
    publicationForText('javascript', javascriptText, options.mutateJavascriptProjection),
    publicationForText('rust', rustText, options.mutateRustProjection),
  ]);
  await Promise.all([
    writeChunkingScaleEvidenceBundle(bundlePaths.javascript, javascript),
    writeChunkingScaleEvidenceBundle(bundlePaths.rust, rust),
  ]);
  const compared = await invokeComparator([
    '--javascript-bundle', bundlePaths.javascript,
    '--rust-bundle', bundlePaths.rust,
    '--output', paths.output,
  ]);
  return { ...compared, bundlePaths };
}

async function assertNoPublishedOutput(paths) {
  const retained = workflowPublicationPaths(paths.output);
  for (const path of [
    paths.output,
    retained.bundlePaths.javascript,
    retained.bundlePaths.rust,
    retained.publicationPaths.javascript,
    retained.publicationPaths.rust,
    retained.validationPaths.javascript,
    retained.validationPaths.rust,
  ]) assert.equal(await lstat(path).catch(() => null), null, path);
}

async function fixture(t, mutate = () => {}) {
  const directory = await mkdtemp(join(tmpdir(), 'ogvcs-chunk-scale-comparison-'));
  t.after(() => rm(directory, { recursive: true, force: true, maxRetries: 8, retryDelay: 50 }));
  const paths = {
    javascript: join(directory, 'javascript.json'),
    rust: join(directory, 'rust.json'),
    output: join(directory, 'comparison.json'),
  };
  const reports = { javascript: report('javascript'), rust: report('rust') };
  mutate(reports);
  const javascriptBytes = Buffer.from(`${JSON.stringify(reports.javascript, null, 2)}\n`);
  const rustBytes = Buffer.from(`${JSON.stringify(reports.rust, null, 2)}\n`);
  await Promise.all([writeFile(paths.javascript, javascriptBytes), writeFile(paths.rust, rustBytes)]);
  return { javascriptBytes, paths, reports, rustBytes };
}

test('literal protected-workflow raw flags publish, retain, verify, and compare both exact-scale reports', async (t) => {
  const value = await fixture(t);
  const compared = await run(['--javascript', value.paths.javascript, '--rust', value.paths.rust, '--output', value.paths.output]);
  assert.equal(compared.code, 0, compared.stderr || compared.stdout);
  const comparison = JSON.parse(await readFile(value.paths.output, 'utf8'));
  assert.equal(comparison.schemaVersion, 'ogvcs.chunking-manifest/scale-comparison/v2');
  assert.equal(comparison.sourceRevision, REVISION);
  assert.equal(comparison.sourceRevisionBinding, 'workflow-supplied-not-git-bound');
  assert.equal(comparison.exactScaleExecuted, true);
  assert.equal(comparison.matched, true);
  assert.deepEqual(comparison.result, RESULT);
  assert.equal(comparison.inputs.javascript.reportSha256, digest(value.javascriptBytes));
  assert.equal(comparison.inputs.rust.reportSha256, digest(value.rustBytes));
  const [javascriptManifest, rustManifest] = await Promise.all([
    readFile(join(compared.bundlePaths.javascript, 'manifest.json'), 'utf8').then(JSON.parse),
    readFile(join(compared.bundlePaths.rust, 'manifest.json'), 'utf8').then(JSON.parse),
  ]);
  assert.equal(comparison.inputs.javascript.bundleDigest, javascriptManifest.bundleDigest);
  assert.equal(comparison.inputs.rust.bundleDigest, rustManifest.bundleDigest);
  const [javascriptPublication, rustPublication, javascriptValidation, rustValidation] = await Promise.all([
    readFile(compared.publicationPaths.javascript, 'utf8').then(JSON.parse),
    readFile(compared.publicationPaths.rust, 'utf8').then(JSON.parse),
    readFile(compared.validationPaths.javascript, 'utf8').then(JSON.parse),
    readFile(compared.validationPaths.rust, 'utf8').then(JSON.parse),
  ]);
  assert.equal(javascriptPublication.schemaVersion, 'ogvcs.chunking-manifest/exact-scale-retained-publication/v1');
  assert.deepEqual(javascriptPublication.artifacts.map(({ path }) => path), ['manifest.json', 'projection.json', 'report.json']);
  assert.equal(JSON.parse(javascriptPublication.artifacts[2].content).implementation, 'javascript');
  assert.equal(JSON.parse(rustPublication.artifacts[2].content).implementation, 'rust');
  assert.equal(comparison.inputs.javascript.publicationSha256, javascriptPublication.publicationSha256);
  assert.equal(comparison.inputs.rust.publicationSha256, rustPublication.publicationSha256);
  assert.equal(javascriptValidation.publicationSha256, javascriptPublication.publicationSha256);
  assert.equal(rustValidation.publicationSha256, rustPublication.publicationSha256);
  assert.equal(javascriptValidation.verified, true);
  assert.equal(rustValidation.verified, true);
  const { comparisonSha256, ...body } = comparison;
  assert.equal(comparisonSha256, canonicalDigest(body, 'ogvcs.chunking-manifest/exact-scale-comparison/v2'));
});

const rejectionCases = [
  { name: 'a JavaScript report claiming no exact execution', mutate: ({ javascript }) => { javascript.exactScaleExecuted = false; }, message: /exactScaleExecuted/u },
  { name: 'a Rust report claiming no exact execution', mutate: ({ rust }) => { rust.exactScaleExecuted = false; }, message: /exactScaleExecuted/u },
  { name: 'a cross-language result mismatch', mutate: ({ rust }) => { rust.result.boundaryTranscriptSha256 = 'e'.repeat(64); }, message: /implementation results differ/u },
  { name: 'a process peak above the declared bound', mutate: ({ javascript }) => { javascript.resources.peakRssBytes = 536_870_913; }, message: /peakRssBytes/u },
  { name: 'a different source revision', mutate: ({ rust }) => { rust.sourceRevision = 'f'.repeat(40); }, message: /source revisions differ/u },
  { name: 'a different runtime architecture', mutate: ({ rust }) => { rust.runtime.architecture = 'arm64'; }, message: /runtime architectures differ/u },
  { name: 'an unreviewed Rust runtime version', mutate: ({ rust }) => { rust.runtime.version = '1.82.0-dev'; }, message: /runtime.version/u },
  { name: 'a mutated source recipe', mutate: ({ javascript }) => { javascript.source.patternSha256 = 'f'.repeat(64); }, message: /source is not the exact declared value/u },
  { name: 'an unrecognized report projection', mutate: ({ javascript }) => { javascript.unreviewed = true; }, message: /unexpected shape/u },
];

for (const rejection of rejectionCases) {
  test(`comparison rejects ${rejection.name}`, async (t) => {
    const value = await fixture(t, rejection.mutate);
    const compared = await run(['--javascript', value.paths.javascript, '--rust', value.paths.rust, '--output', value.paths.output]);
    assert.notEqual(compared.code, 0);
    assert.match(compared.stderr, rejection.message);
    await assertNoPublishedOutput(value.paths);
  });
}

test('comparison rejects a content-bound projection whose report digest is substituted', async (t) => {
  const value = await fixture(t);
  const compared = await run(['--javascript', value.paths.javascript, '--rust', value.paths.rust, '--output', value.paths.output], {
    mutateJavascriptProjection(projection) { projection.reportSha256 = 'f'.repeat(64); },
  });
  assert.notEqual(compared.code, 0);
  assert.match(compared.stderr, /projection does not reproduce/u);
  await assert.rejects(readFile(value.paths.output), { code: 'ENOENT' });
});

test('comparison rejects malformed and missing content-bound report projections', async (t) => {
  const malformed = await fixture(t);
  await writeFile(malformed.paths.javascript, '{\n');
  const malformedResult = await run(['--javascript', malformed.paths.javascript, '--rust', malformed.paths.rust, '--output', malformed.paths.output]);
  assert.notEqual(malformedResult.code, 0);
  assert.match(malformedResult.stderr, /report is not JSON/u);
  await assertNoPublishedOutput(malformed.paths);

  const missing = await fixture(t);
  const missingResult = await run(['--javascript', missing.paths.javascript, '--rust', missing.paths.rust, '--output', missing.paths.output], {
    mutateRustProjection(projection) { delete projection.reportSha256; },
  });
  assert.notEqual(missingResult.code, 0);
  assert.match(missingResult.stderr, /projection does not reproduce/u);
  await assert.rejects(readFile(missing.paths.output), { code: 'ENOENT' });
});

test('comparison rejects implementation substitution and a missing content-addressed bundle artifact', async (t) => {
  const value = await fixture(t);
  const compared = await run(['--javascript', value.paths.javascript, '--rust', value.paths.rust, '--output', value.paths.output]);
  assert.equal(compared.code, 0, compared.stderr);

  const substitutedOutput = join(dirname(value.paths.output), 'substituted.json');
  const substituted = await invokeComparator([
    '--javascript-bundle', compared.bundlePaths.rust,
    '--rust-bundle', compared.bundlePaths.javascript,
    '--output', substitutedOutput,
  ]);
  assert.notEqual(substituted.code, 0);
  assert.match(substituted.stderr, /implementation differs|implementation is invalid|bundle manifest authority/u);
  await assert.rejects(readFile(substitutedOutput), { code: 'ENOENT' });

  const missingBundle = join(dirname(value.paths.output), 'missing-artifact-javascript-bundle');
  await cp(compared.bundlePaths.javascript, missingBundle, { recursive: true });
  await unlink(join(missingBundle, 'report.json'));
  const missingOutput = join(dirname(value.paths.output), 'missing.json');
  const missing = await invokeComparator([
    '--javascript-bundle', missingBundle,
    '--rust-bundle', compared.bundlePaths.rust,
    '--output', missingOutput,
  ]);
  assert.notEqual(missing.code, 0);
  assert.match(missing.stderr, /inventory is incomplete or unexpected/u);
  await assert.rejects(readFile(missingOutput), { code: 'ENOENT' });
});

test('comparison rejects mixed raw-report and prepublished-bundle surfaces', async (t) => {
  const value = await fixture(t);
  const compared = await invokeComparator([
    '--javascript', value.paths.javascript,
    '--rust-bundle', join(dirname(value.paths.output), 'rust-bundle'),
    '--output', value.paths.output,
  ]);
  assert.notEqual(compared.code, 0);
  assert.match(compared.stderr, /unknown argument --rust-bundle|usage: --javascript/u);
  await assert.rejects(readFile(value.paths.output), { code: 'ENOENT' });
});

test('retained publication verification rejects embedded projection tamper', async (t) => {
  const value = await fixture(t);
  const compared = await run(['--javascript', value.paths.javascript, '--rust', value.paths.rust, '--output', value.paths.output]);
  assert.equal(compared.code, 0, compared.stderr);
  const publication = JSON.parse(await readFile(compared.publicationPaths.javascript, 'utf8'));
  publication.artifacts[1].content = publication.artifacts[1].content.replace('"overallStatus":"passed"', '"overallStatus":"failed"');
  await writeFile(compared.publicationPaths.javascript, `${canonicalJson(publication)}\n`);
  const output = join(dirname(value.paths.output), 'tampered-validation.json');
  const verified = await new Promise((resolvePromise, reject) => {
    const child = spawn(process.execPath, [
      'tools/verify-chunking-scale-evidence-bundle.mjs',
      '--implementation', 'javascript',
      '--publication', compared.publicationPaths.javascript,
      '--output', output,
    ], { cwd: SCALE_ROOT, stdio: ['ignore', 'pipe', 'pipe'] });
    const stderr = [];
    child.stderr.on('data', (chunk) => stderr.push(chunk));
    child.once('error', reject);
    child.once('close', (code) => resolvePromise({ code, stderr: Buffer.concat(stderr).toString('utf8') }));
  });
  assert.notEqual(verified.code, 0);
  assert.match(verified.stderr, /retained publication does not reproduce|projection does not reproduce/u);
  await assert.rejects(readFile(output), { code: 'ENOENT' });
});

test('every raw-workflow create-new writer fault leaves no partial publication', { timeout: 120_000 }, async (t) => {
  for (const stage of [
    'javascript-bundle',
    'rust-bundle',
    'javascript-publication',
    'rust-publication',
    'javascript-validation',
    'rust-validation',
    'comparison',
  ]) {
    const value = await fixture(t);
    const args = ['--javascript', value.paths.javascript, '--rust', value.paths.rust, '--output', value.paths.output];
    await assert.rejects(runRawWorkflowPublicationForTest(args, stage), /injected .*parent-sync failure/u, stage);
    await assertNoPublishedOutput(value.paths);
  }
});

test('every writer failure path uses the shared unlink-and-parent-sync cleanup', async () => {
  const [common, comparator, verifier, workflow] = await Promise.all([
    readFile(join(SCALE_ROOT, 'tools/chunking-scale-evidence-common.mjs'), 'utf8'),
    readFile(join(SCALE_ROOT, 'tools/chunking-scale-evidence-comparator.mjs'), 'utf8'),
    readFile(join(SCALE_ROOT, 'tools/verify-chunking-scale-evidence-bundle.mjs'), 'utf8'),
    readFile(join(SCALE_ROOT, 'tools/compare-chunking-scale.mjs'), 'utf8'),
  ]);
  assert.match(common, /export async function removeScalePublicationPathDurably[\s\S]*await rm\(path,[\s\S]*await syncScalePublicationDirectory\(dirname\(path\)\)/u);
  assert.match(comparator, /if \(created\) await removeScalePublicationPathDurably\(path\)/u);
  assert.match(verifier, /if \(created\) await removeScalePublicationPathDurably\(path\)/u);
  assert.match(workflow, /await removeScalePublicationPathDurably\(path, path\.endsWith\('\.bundle'\)\)/u);
  assert.doesNotMatch(workflow, /rm\(path, \{ recursive: true, force: true \}\)\.catch/u);
});
