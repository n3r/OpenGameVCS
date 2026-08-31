import { createHash } from 'node:crypto';
import { readFile, stat, writeFile } from 'node:fs/promises';

const REPORT_BYTES_MAXIMUM = 1024 * 1024;
const LOGICAL_BYTES = '107374182400';
const PROFILE = 'chunking.opengamevcs/gear-fastcdc-1m@1';
const SHA256 = /^[0-9a-f]{64}$/u;
const SOURCE_REVISION = /^[0-9a-f]{40}$/u;
const MANIFEST_OBJECT_ID = /^ogvcs:v1:content-manifest:sha256:[0-9a-f]{64}$/u;
const SOURCE = Object.freeze({
  schemaVersion: 'ogvcs.chunking-manifest/scale-source-repeated-lcg-v1',
  logicalBytes: LOGICAL_BYTES,
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

function fail(message) {
  throw new Error(`chunking exact-scale comparison failure: ${message}`);
}

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function digest(value) {
  return createHash('sha256').update(value).digest('hex');
}

function exactKeys(value, expected, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) fail(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (canonical(actual) !== canonical(wanted)) fail(`${label} has an unexpected shape`);
}

function exactObject(value, expected, label) {
  exactKeys(value, Object.keys(expected), label);
  if (canonical(value) !== canonical(expected)) fail(`${label} is not the exact declared value`);
}

function integer(value, label, { minimum = 0, maximum = Number.MAX_SAFE_INTEGER } = {}) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    fail(`${label} must be an integer in [${minimum}, ${maximum}]`);
  }
}

function matching(value, expression, label) {
  if (typeof value !== 'string' || !expression.test(value)) fail(`${label} is invalid`);
}

function validateRuntime(runtime, implementation) {
  exactKeys(runtime, ['architecture', 'os', 'version'], `${implementation}.runtime`);
  if (runtime.os !== 'linux') fail(`${implementation}.runtime.os must be linux`);
  if (!['x64', 'arm64'].includes(runtime.architecture)) fail(`${implementation}.runtime.architecture is unsupported`);
  const version = implementation === 'javascript' ? /^v24\.[0-9]+\.[0-9]+$/u : /^1\.82\.0$/u;
  matching(runtime.version, version, `${implementation}.runtime.version`);
}

function validateResult(result, implementation) {
  exactKeys(result, [
    'boundaryTranscriptSha256', 'chunkCount', 'class', 'logicalBytes', 'manifestBytes',
    'manifestObjectId', 'manifestSha256', 'maximumChunkBytes', 'minimumChunkBytes',
    'totalChunkBytes', 'wholeFileSha256',
  ], `${implementation}.result`);
  if (result.class !== 'cdc-1m') fail(`${implementation}.result.class is invalid`);
  if (result.logicalBytes !== LOGICAL_BYTES || result.totalChunkBytes !== LOGICAL_BYTES) {
    fail(`${implementation}.result does not account for exactly 100 GiB`);
  }
  integer(result.chunkCount, `${implementation}.result.chunkCount`, { minimum: 1, maximum: 1_048_576 });
  integer(result.minimumChunkBytes, `${implementation}.result.minimumChunkBytes`, { minimum: 1, maximum: 2_097_152 });
  integer(result.maximumChunkBytes, `${implementation}.result.maximumChunkBytes`, {
    minimum: result.minimumChunkBytes,
    maximum: 2_097_152,
  });
  const logicalBytes = Number(LOGICAL_BYTES);
  if (logicalBytes < result.chunkCount * result.minimumChunkBytes
      || logicalBytes > result.chunkCount * result.maximumChunkBytes) {
    fail(`${implementation}.result chunk extrema cannot account for exactly 100 GiB`);
  }
  integer(result.manifestBytes, `${implementation}.result.manifestBytes`, { minimum: 1 });
  matching(result.wholeFileSha256, SHA256, `${implementation}.result.wholeFileSha256`);
  matching(result.manifestObjectId, MANIFEST_OBJECT_ID, `${implementation}.result.manifestObjectId`);
  matching(result.manifestSha256, SHA256, `${implementation}.result.manifestSha256`);
  matching(result.boundaryTranscriptSha256, SHA256, `${implementation}.result.boundaryTranscriptSha256`);
}

function validateResources(resources, result, implementation) {
  exactKeys(resources, [
    'ledgerPeakMemoryBytes', 'ledgerPeakScratchBytes', 'ledgerRecords', 'ledgerSpilled',
    'maxRssSource', 'patternBufferBytes', 'peakRssBytes', 'scalarWorkingMemoryBytes',
    'scratchArtifactsAfter', 'throughputBytesPerSecond', 'wallTimeMilliseconds',
  ], `${implementation}.resources`);
  integer(resources.wallTimeMilliseconds, `${implementation}.resources.wallTimeMilliseconds`, {
    minimum: 1,
    maximum: BOUNDS.wallTimeMillisecondsMaximum,
  });
  integer(resources.throughputBytesPerSecond, `${implementation}.resources.throughputBytesPerSecond`, { minimum: 1 });
  integer(resources.peakRssBytes, `${implementation}.resources.peakRssBytes`, {
    minimum: 1,
    maximum: BOUNDS.peakRssBytesMaximum,
  });
  integer(resources.patternBufferBytes, `${implementation}.resources.patternBufferBytes`, {
    minimum: SOURCE.patternBytes,
    maximum: SOURCE.patternBytes,
  });
  integer(resources.scalarWorkingMemoryBytes, `${implementation}.resources.scalarWorkingMemoryBytes`, {
    minimum: 4_259_840,
    maximum: 4_259_840,
  });
  integer(resources.ledgerRecords, `${implementation}.resources.ledgerRecords`, {
    minimum: result.chunkCount,
    maximum: result.chunkCount,
  });
  integer(resources.ledgerPeakMemoryBytes, `${implementation}.resources.ledgerPeakMemoryBytes`, {
    minimum: 1,
    maximum: BOUNDS.ledgerMemoryBytesMaximum,
  });
  integer(resources.ledgerPeakScratchBytes, `${implementation}.resources.ledgerPeakScratchBytes`, {
    minimum: 1,
    maximum: BOUNDS.ledgerScratchBytesMaximum,
  });
  integer(resources.scratchArtifactsAfter, `${implementation}.resources.scratchArtifactsAfter`, {
    minimum: 0,
    maximum: 0,
  });
  if (resources.ledgerSpilled !== true) fail(`${implementation}.resources.ledgerSpilled must be true`);
  const expectedRssSource = implementation === 'javascript'
    ? 'node:process.resourceUsage().maxRSS-kib'
    : 'linux:/proc/self/status:VmHWM-kib';
  if (resources.maxRssSource !== expectedRssSource) fail(`${implementation}.resources.maxRssSource is invalid`);
}

function validateReport(report, implementation) {
  exactKeys(report, [
    'bounds', 'exactScaleExecuted', 'implementation', 'overallStatus', 'profile', 'resources',
    'result', 'runtime', 'schemaVersion', 'source', 'sourceRevision',
  ], implementation);
  if (report.schemaVersion !== 'ogvcs.chunking-manifest/scale-report/v1') fail(`${implementation}.schemaVersion is invalid`);
  if (report.implementation !== implementation) fail(`${implementation}.implementation is invalid`);
  if (report.profile !== PROFILE) fail(`${implementation}.profile is invalid`);
  matching(report.sourceRevision, SOURCE_REVISION, `${implementation}.sourceRevision`);
  if (report.exactScaleExecuted !== true) fail(`${implementation}.exactScaleExecuted must be true`);
  if (report.overallStatus !== 'passed') fail(`${implementation}.overallStatus must be passed`);
  validateRuntime(report.runtime, implementation);
  exactObject(report.source, SOURCE, `${implementation}.source`);
  validateResult(report.result, implementation);
  validateResources(report.resources, report.result, implementation);
  exactObject(report.bounds, BOUNDS, `${implementation}.bounds`);
}

function parseArguments(argv) {
  const paths = Object.create(null);
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (!['--javascript', '--rust', '--output'].includes(flag) || typeof value !== 'string' || value.length === 0) {
      fail('usage: --javascript <report> --rust <report> --output <comparison>');
    }
    const key = flag.slice(2);
    if (paths[key] !== undefined) fail(`${flag} was provided more than once`);
    paths[key] = value;
  }
  if (argv.length !== 6 || paths.javascript === undefined || paths.rust === undefined || paths.output === undefined) {
    fail('usage: --javascript <report> --rust <report> --output <comparison>');
  }
  return paths;
}

async function loadReport(path, implementation) {
  const metadata = await stat(path);
  if (!metadata.isFile() || metadata.size > REPORT_BYTES_MAXIMUM) {
    fail(`${implementation} report must be one regular file no larger than 1 MiB`);
  }
  const bytes = await readFile(path);
  if (bytes.byteLength > REPORT_BYTES_MAXIMUM) fail(`${implementation} report exceeds 1 MiB`);
  let report;
  try {
    report = JSON.parse(bytes.toString('utf8'));
  } catch {
    fail(`${implementation} report is not JSON`);
  }
  validateReport(report, implementation);
  return { bytes, report };
}

const paths = parseArguments(process.argv.slice(2));
const [javascript, rust] = await Promise.all([
  loadReport(paths.javascript, 'javascript'),
  loadReport(paths.rust, 'rust'),
]);

if (javascript.report.sourceRevision !== rust.report.sourceRevision) fail('source revisions differ');
if (javascript.report.runtime.architecture !== rust.report.runtime.architecture) fail('runtime architectures differ');
if (canonical(javascript.report.result) !== canonical(rust.report.result)) fail('implementation results differ');

const body = {
  schemaVersion: 'ogvcs.chunking-manifest/scale-comparison/v1',
  profile: PROFILE,
  sourceRevision: javascript.report.sourceRevision,
  exactScaleExecuted: true,
  matched: true,
  source: SOURCE,
  result: javascript.report.result,
  bounds: BOUNDS,
  inputs: {
    javascript: {
      reportSha256: digest(javascript.bytes),
      runtime: javascript.report.runtime,
      resources: javascript.report.resources,
    },
    rust: {
      reportSha256: digest(rust.bytes),
      runtime: rust.report.runtime,
      resources: rust.report.resources,
    },
  },
};
const comparison = { ...body, comparisonSha256: digest(canonical(body)) };
await writeFile(paths.output, `${JSON.stringify(comparison, null, 2)}\n`, {
  encoding: 'utf8',
  flag: 'wx',
  mode: 0o600,
});
