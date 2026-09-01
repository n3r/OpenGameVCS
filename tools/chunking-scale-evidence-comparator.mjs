import { mkdir, open } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';

import { canonicalDigest, canonicalJson } from '../foundation/benchmark-fault-harness/src/index.mjs';
import {
  SCALE_BOUNDS,
  SCALE_COMPARISON_SCHEMA_VERSION,
  SCALE_PROFILE,
  SCALE_SOURCE,
  removeScalePublicationPathDurably,
  syncScalePublicationDirectory,
} from './chunking-scale-evidence-common.mjs';
import {
  inspectVerifiedChunkingScaleEvidence,
  verifyChunkingScaleEvidenceBundle,
} from './verify-chunking-scale-evidence-bundle.mjs';

function fail(message) {
  throw new Error(`chunking exact-scale comparison failure: ${message}`);
}

function parseArguments(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 2) {
    if (index + 1 >= argv.length) fail('usage: --javascript-bundle <dir> --rust-bundle <dir> --output <comparison.json>');
    const flag = argv[index];
    const value = argv[index + 1];
    if (typeof value !== 'string' || value.length === 0) fail(`${flag} value is missing`);
    if (flag === '--javascript-bundle') options.javascriptBundle = resolve(process.cwd(), value);
    else if (flag === '--rust-bundle') options.rustBundle = resolve(process.cwd(), value);
    else if (flag === '--output') options.output = resolve(process.cwd(), value);
    else fail(`unknown argument ${flag}`);
  }
  if (argv.length !== 6 || !options.javascriptBundle || !options.rustBundle || !options.output) {
    fail('usage: --javascript-bundle <dir> --rust-bundle <dir> --output <comparison.json>');
  }
  return options;
}

export function compareVerifiedChunkingScaleEvidence(javascriptHandle, rustHandle) {
  const javascript = inspectVerifiedChunkingScaleEvidence(javascriptHandle);
  const rust = inspectVerifiedChunkingScaleEvidence(rustHandle);
  if (javascript.implementation !== 'javascript' || rust.implementation !== 'rust') fail('verified implementations are substituted');
  if (javascript.sourceRevision !== rust.sourceRevision) fail('source revisions differ');
  if (javascript.sourceRevisionBinding !== rust.sourceRevisionBinding) fail('source revision bindings differ');
  if (javascript.report.runtime.architecture !== rust.report.runtime.architecture) fail('runtime architectures differ');
  if (canonicalJson(javascript.report.source) !== canonicalJson(rust.report.source)) fail('source recipes differ');
  if (canonicalJson(javascript.report.bounds) !== canonicalJson(rust.report.bounds)) fail('declared bounds differ');
  if (canonicalJson(javascript.report.result) !== canonicalJson(rust.report.result)) fail('implementation results differ');
  const body = {
    schemaVersion: SCALE_COMPARISON_SCHEMA_VERSION,
    profile: SCALE_PROFILE,
    sourceRevision: javascript.sourceRevision,
    sourceRevisionBinding: javascript.sourceRevisionBinding,
    exactScaleExecuted: true,
    matched: true,
    source: SCALE_SOURCE,
    result: javascript.report.result,
    bounds: SCALE_BOUNDS,
    inputs: {
      javascript: {
        bundleDigest: javascript.bundleDigest,
        publicationSha256: javascript.publicationSha256,
        reportSha256: javascript.reportSha256,
        runtime: javascript.report.runtime,
        resources: javascript.report.resources,
      },
      rust: {
        bundleDigest: rust.bundleDigest,
        publicationSha256: rust.publicationSha256,
        reportSha256: rust.reportSha256,
        runtime: rust.report.runtime,
        resources: rust.report.resources,
      },
    },
  };
  return Object.freeze({
    ...body,
    comparisonSha256: canonicalDigest(body, 'ogvcs.chunking-manifest/exact-scale-comparison/v2'),
  });
}

async function writeCreateNew(path, text, optionsForTest = undefined) {
  const parent = dirname(path);
  await mkdir(parent, { recursive: true });
  let handle;
  let created = false;
  try {
    handle = await open(path, 'wx', 0o600);
    created = true;
    await handle.writeFile(text, 'utf8');
    await handle.sync();
    if (optionsForTest?.failAfterPublish === true) throw new Error('injected comparison parent-sync failure');
    await syncScalePublicationDirectory(parent);
  } catch (error) {
    await handle?.close().catch(() => {});
    if (created) await removeScalePublicationPathDurably(path);
    throw error;
  } finally {
    await handle?.close().catch(() => {});
  }
}

export async function writeChunkingScaleComparison(path, javascriptHandle, rustHandle, optionsForTest = undefined) {
  const comparison = compareVerifiedChunkingScaleEvidence(javascriptHandle, rustHandle);
  await writeCreateNew(path, `${canonicalJson(comparison)}\n`, optionsForTest);
  return comparison;
}

export async function runChunkingScaleComparisonCli(argv) {
  const options = parseArguments(argv);
  const [javascript, rust] = await Promise.all([
    verifyChunkingScaleEvidenceBundle(options.javascriptBundle, 'javascript'),
    verifyChunkingScaleEvidenceBundle(options.rustBundle, 'rust'),
  ]);
  const comparison = await writeChunkingScaleComparison(options.output, javascript, rust);
  return Object.freeze({
    schemaVersion: 'ogvcs.chunking-manifest/exact-scale-comparison-validation/v1',
    comparisonSha256: comparison.comparisonSha256,
    sourceRevision: comparison.sourceRevision,
    sourceRevisionBinding: comparison.sourceRevisionBinding,
    verified: true,
  });
}
