#!/usr/bin/env node

import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalJson } from '../foundation/benchmark-fault-harness/src/index.mjs';
import {
  buildChunkingScaleEvidenceBundle,
  buildRetainedChunkingScalePublication,
  writeChunkingScaleEvidenceBundle,
  writeRetainedChunkingScalePublication,
} from './chunking-scale-evidence-bundle.mjs';
import {
  runChunkingScaleComparisonCli,
  writeChunkingScaleComparison,
} from './chunking-scale-evidence-comparator.mjs';
import { loadScaleReport, removeScalePublicationPathDurably } from './chunking-scale-evidence-common.mjs';
import {
  verifyChunkingScaleEvidenceBundle,
  verifyRetainedChunkingScalePublication,
  writeChunkingScaleEvidenceValidation,
} from './verify-chunking-scale-evidence-bundle.mjs';

const RAW_USAGE = 'usage: --javascript <report.json> --rust <report.json> --output <comparison.json>';
const WRITER_FAILURE_STAGES = Object.freeze([
  'javascript-bundle', 'rust-bundle', 'javascript-publication', 'rust-publication',
  'javascript-validation', 'rust-validation', 'comparison',
]);

function fail(message) {
  throw new Error(`chunking exact-scale workflow publication failure: ${message}`);
}

function parseRawArguments(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 2) {
    if (index + 1 >= argv.length) fail(RAW_USAGE);
    const flag = argv[index];
    const value = argv[index + 1];
    if (typeof value !== 'string' || value.length === 0) fail(`${flag} value is missing`);
    if (flag === '--javascript') options.javascript = resolve(process.cwd(), value);
    else if (flag === '--rust') options.rust = resolve(process.cwd(), value);
    else if (flag === '--output') options.output = resolve(process.cwd(), value);
    else fail(`unknown argument ${flag}`);
  }
  if (argv.length !== 6 || !options.javascript || !options.rust || !options.output) fail(RAW_USAGE);
  return options;
}

export function retainedWorkflowPaths(output) {
  const name = basename(output);
  const stem = name.endsWith('.json') ? name.slice(0, -'.json'.length) : name;
  const parent = dirname(output);
  return Object.freeze({
    javascriptBundle: join(parent, `${stem}.javascript.bundle`),
    rustBundle: join(parent, `${stem}.rust.bundle`),
    javascriptPublication: join(parent, `${stem}.javascript.publication.json`),
    rustPublication: join(parent, `${stem}.rust.publication.json`),
    javascriptValidation: join(parent, `${stem}.javascript.validation.json`),
    rustValidation: join(parent, `${stem}.rust.validation.json`),
  });
}

function writerFault(stage, requestedStage) {
  return stage === requestedStage ? Object.freeze({ failAfterPublish: true }) : undefined;
}

async function runRawWorkflowPublication(argv, writerFailureStage = undefined) {
  if (writerFailureStage !== undefined && !WRITER_FAILURE_STAGES.includes(writerFailureStage)) fail('test writer failure stage is invalid');
  const options = parseRawArguments(argv);
  const paths = retainedWorkflowPaths(options.output);
  const owned = [];
  try {
    const [javascriptRecord, rustRecord] = await Promise.all([
      loadScaleReport(options.javascript, 'javascript'),
      loadScaleReport(options.rust, 'rust'),
    ]);
    const [javascriptBuilt, rustBuilt] = await Promise.all([
      buildChunkingScaleEvidenceBundle({ implementation: 'javascript', reportRecord: javascriptRecord }),
      buildChunkingScaleEvidenceBundle({ implementation: 'rust', reportRecord: rustRecord }),
    ]);
    const javascriptPublication = buildRetainedChunkingScalePublication(javascriptBuilt);
    const rustPublication = buildRetainedChunkingScalePublication(rustBuilt);

    await writeChunkingScaleEvidenceBundle(paths.javascriptBundle, javascriptBuilt, writerFault('javascript-bundle', writerFailureStage));
    owned.push(paths.javascriptBundle);
    await writeChunkingScaleEvidenceBundle(paths.rustBundle, rustBuilt, writerFault('rust-bundle', writerFailureStage));
    owned.push(paths.rustBundle);
    await Promise.all([
      verifyChunkingScaleEvidenceBundle(paths.javascriptBundle, 'javascript'),
      verifyChunkingScaleEvidenceBundle(paths.rustBundle, 'rust'),
    ]);

    await writeRetainedChunkingScalePublication(paths.javascriptPublication, javascriptPublication, writerFault('javascript-publication', writerFailureStage));
    owned.push(paths.javascriptPublication);
    await writeRetainedChunkingScalePublication(paths.rustPublication, rustPublication, writerFault('rust-publication', writerFailureStage));
    owned.push(paths.rustPublication);
    const [javascript, rust] = await Promise.all([
      verifyRetainedChunkingScalePublication(paths.javascriptPublication, 'javascript'),
      verifyRetainedChunkingScalePublication(paths.rustPublication, 'rust'),
    ]);

    await writeChunkingScaleEvidenceValidation(paths.javascriptValidation, javascript, writerFault('javascript-validation', writerFailureStage));
    owned.push(paths.javascriptValidation);
    await writeChunkingScaleEvidenceValidation(paths.rustValidation, rust, writerFault('rust-validation', writerFailureStage));
    owned.push(paths.rustValidation);
    const comparison = await writeChunkingScaleComparison(options.output, javascript, rust, writerFault('comparison', writerFailureStage));
    return Object.freeze({
      schemaVersion: 'ogvcs.chunking-manifest/exact-scale-workflow-publication-validation/v1',
      comparisonSha256: comparison.comparisonSha256,
      javascriptPublicationSha256: javascriptPublication.publicationSha256,
      rustPublicationSha256: rustPublication.publicationSha256,
      sourceRevision: comparison.sourceRevision,
      sourceRevisionBinding: comparison.sourceRevisionBinding,
      verified: true,
    });
  } catch (error) {
    let cleanupFailed = false;
    for (const path of owned.reverse()) {
      try { await removeScalePublicationPathDurably(path, path.endsWith('.bundle')); } catch { cleanupFailed = true; }
    }
    if (cleanupFailed) fail('durable campaign cleanup cannot be proven');
    throw error;
  }
}

export async function runRawWorkflowPublicationForTest(argv, writerFailureStage) {
  return runRawWorkflowPublication(argv, writerFailureStage);
}

async function main() {
  const argv = process.argv.slice(2);
  const validation = argv.includes('--javascript') || argv.includes('--rust')
    ? await runRawWorkflowPublication(argv)
    : await runChunkingScaleComparisonCli(argv);
  process.stdout.write(`${canonicalJson(validation)}\n`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) await main();
