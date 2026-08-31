import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

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
const BOUNDS = Object.freeze({
  wallTimeMillisecondsMaximum: 18_000_000,
  peakRssBytesMaximum: 536_870_912,
  ledgerMemoryBytesMaximum: 1_048_576,
  ledgerScratchBytesMaximum: 67_108_864,
  temporaryWholeFileAllowed: false,
});
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

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

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
      throughputBytesPerSecond: 53_687_091,
      peakRssBytes: 201_326_592,
      maxRssSource: implementation === 'javascript'
        ? 'node:process.resourceUsage().maxRSS-kib'
        : 'linux:/proc/self/status:VmHWM-kib',
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

function run(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['tools/compare-chunking-scale.mjs', ...args], {
      cwd: new URL('../', import.meta.url),
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const stdout = [];
    const stderr = [];
    child.stdout.on('data', (chunk) => stdout.push(chunk));
    child.stderr.on('data', (chunk) => stderr.push(chunk));
    child.once('error', reject);
    child.once('close', (code) => resolve({
      code,
      stdout: Buffer.concat(stdout).toString('utf8'),
      stderr: Buffer.concat(stderr).toString('utf8'),
    }));
  });
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
  const javascriptBytes = Buffer.from(`${JSON.stringify(reports.javascript)}\n`);
  const rustBytes = Buffer.from(`${JSON.stringify(reports.rust)}\n`);
  await Promise.all([
    writeFile(paths.javascript, javascriptBytes),
    writeFile(paths.rust, rustBytes),
  ]);
  return { javascriptBytes, paths, reports, rustBytes };
}

test('comparison accepts only matching exact 100-GiB reports and binds both inputs', async (t) => {
  const value = await fixture(t);
  const compared = await run([
    '--javascript', value.paths.javascript,
    '--rust', value.paths.rust,
    '--output', value.paths.output,
  ]);
  assert.equal(compared.code, 0, compared.stderr || compared.stdout);
  const comparison = JSON.parse(await readFile(value.paths.output, 'utf8'));
  assert.equal(comparison.schemaVersion, 'ogvcs.chunking-manifest/scale-comparison/v1');
  assert.equal(comparison.sourceRevision, REVISION);
  assert.equal(comparison.exactScaleExecuted, true);
  assert.equal(comparison.matched, true);
  assert.deepEqual(comparison.result, RESULT);
  assert.equal(comparison.inputs.javascript.reportSha256, digest(value.javascriptBytes));
  assert.equal(comparison.inputs.rust.reportSha256, digest(value.rustBytes));
  const { comparisonSha256, ...body } = comparison;
  assert.equal(comparisonSha256, digest(canonical(body)));
});

const rejectionCases = [
  {
    name: 'a bounded report claiming no exact execution',
    mutate: ({ javascript }) => { javascript.exactScaleExecuted = false; },
    message: /exactScaleExecuted/u,
  },
  {
    name: 'a cross-language result mismatch',
    mutate: ({ rust }) => { rust.result.boundaryTranscriptSha256 = 'e'.repeat(64); },
    message: /implementation results differ/u,
  },
  {
    name: 'a process peak above the declared bound',
    mutate: ({ javascript }) => { javascript.resources.peakRssBytes = 536_870_913; },
    message: /peakRssBytes/u,
  },
  {
    name: 'a different source revision',
    mutate: ({ rust }) => { rust.sourceRevision = 'f'.repeat(40); },
    message: /source revisions differ/u,
  },
  {
    name: 'an unreviewed Rust runtime version',
    mutate: ({ rust }) => { rust.runtime.version = '1.82.0-dev'; },
    message: /runtime.version/u,
  },
  {
    name: 'a mutated source recipe',
    mutate: ({ javascript }) => { javascript.source.patternSha256 = 'f'.repeat(64); },
    message: /source is not the exact declared value/u,
  },
  {
    name: 'an unrecognized report projection',
    mutate: ({ javascript }) => { javascript.unreviewed = true; },
    message: /unexpected shape/u,
  },
];

for (const rejection of rejectionCases) {
  test(`comparison rejects ${rejection.name}`, async (t) => {
    const value = await fixture(t, rejection.mutate);
    const compared = await run([
      '--javascript', value.paths.javascript,
      '--rust', value.paths.rust,
      '--output', value.paths.output,
    ]);
    assert.notEqual(compared.code, 0);
    assert.match(compared.stderr, rejection.message);
    await assert.rejects(readFile(value.paths.output));
  });
}
