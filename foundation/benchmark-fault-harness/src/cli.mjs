import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { parseArgs } from 'node:util';

import { verifyResultBundle } from './bundle.mjs';
import { canonicalJson } from './canonical.mjs';
import { compareResultBundles } from './comparison.mjs';
import { loadBenchmarkContract } from './contract.mjs';
import { asHarnessError } from './errors.mjs';
import { runFaultMatrix, runBrokenServiceSelfTest } from './fault-harness.mjs';
import { planHarnessMatrix, runReferenceHarness } from './harness.mjs';

export const CLI_HELP = `OpenGameVCS benchmark and fault harness

Usage:
  ogvcs-benchmark smoke [--output <directory>] [--profile <name>] [--seed <text>]
  ogvcs-benchmark plan [--contract <directory>]
  ogvcs-benchmark faults [--contract <directory>]
  ogvcs-benchmark verify --bundle <directory> [--contract <directory>]
  ogvcs-benchmark compare --baseline <directory> --candidate <directory> [--tolerance-ppm <integer>]

Normal smoke and presubmit profiles are unprivileged. Privileged network
profiles exist only in the isolated manual release matrix. Exact large-scale
fixture campaigns are never run by these ordinary commands.
`;

function number(value, name) {
  if (value === undefined) return undefined;
  if (!/^(?:0|[1-9][0-9]*)$/u.test(value) || !Number.isSafeInteger(Number(value))) throw new Error(`${name} must be a canonical integer`);
  return Number(value);
}

function assertCommandShape(command, parsed) {
  const allowed = {
    plan: ['contract', 'output'],
    faults: ['contract', 'output', 'seed'],
    verify: ['bundle', 'contract', 'output'],
    compare: ['baseline', 'candidate', 'contract', 'output', 'tolerance-ppm'],
    smoke: ['classification', 'contract', 'iterations', 'operator', 'output', 'profile', 'seed', 'workspace'],
  }[command];
  if (!allowed || parsed.positionals.length !== 1) throw new Error(allowed ? `${command} accepts exactly one command positional` : `unknown command: ${command}`);
  const accepted = new Set(['help', ...allowed]);
  for (const [name, value] of Object.entries(parsed.values)) if (value !== undefined && value !== false && !accepted.has(name)) throw new Error(`--${name} is not valid for ${command}`);
}

async function machineWrite(path, value) {
  const text = `${canonicalJson(value)}\n`;
  if (path) await writeFile(path, text, { encoding: 'utf8', flag: 'wx' }); else process.stdout.write(text);
}

export async function runCli(argv = process.argv.slice(2)) {
  const parsed = parseArgs({ args: argv, allowPositionals: true, strict: true, options: {
    help: { type: 'boolean', short: 'h', default: false }, contract: { type: 'string' }, output: { type: 'string' }, profile: { type: 'string' }, seed: { type: 'string' }, workspace: { type: 'string' }, operator: { type: 'string' }, classification: { type: 'string' }, iterations: { type: 'string' }, bundle: { type: 'string' }, baseline: { type: 'string' }, candidate: { type: 'string' }, 'tolerance-ppm': { type: 'string' },
  } });
  if (parsed.values.help || parsed.positionals.length === 0) { process.stdout.write(CLI_HELP); return 0; }
  const command = parsed.positionals[0];
  assertCommandShape(command, parsed);
  const contract = await loadBenchmarkContract({ ...(parsed.values.contract ? { root: parsed.values.contract } : {}), cache: false });
  if (command === 'plan') { await machineWrite(parsed.values.output, { schemaVersion: 'ogvcs.benchmark/matrix-plan/v1', contractManifestSha256: contract.manifestSha256, profiles: planHarnessMatrix(contract) }); return 0; }
  if (command === 'faults') {
    const [matrix, broken] = await Promise.all([runFaultMatrix(contract, { seed: parsed.values.seed }), runBrokenServiceSelfTest(contract)]);
    await machineWrite(parsed.values.output, { schemaVersion: 'ogvcs.benchmark/fault-proof/v1', contractManifestSha256: contract.manifestSha256, matrix, broken, passed: matrix.failed === 0 && broken.missed === 0 }); return matrix.failed === 0 && broken.missed === 0 ? 0 : 1;
  }
  if (command === 'verify') {
    if (!parsed.values.bundle) throw new Error('--bundle is required'); const result = await verifyResultBundle(resolve(parsed.values.bundle), contract);
    await machineWrite(parsed.values.output, { verified: result.verified, bundleDigest: result.manifest.bundleDigest, runId: result.result.runId, status: result.result.overallStatus }); return result.result.overallStatus === 'passed' ? 0 : 1;
  }
  if (command === 'compare') {
    if (!parsed.values.baseline || !parsed.values.candidate) throw new Error('--baseline and --candidate are required');
    const [baseline, candidate] = await Promise.all([verifyResultBundle(resolve(parsed.values.baseline), contract), verifyResultBundle(resolve(parsed.values.candidate), contract)]);
    const report = compareResultBundles(contract, baseline, candidate, { tolerancePartsPerMillion: number(parsed.values['tolerance-ppm'], '--tolerance-ppm') });
    await machineWrite(parsed.values.output, report); return report.reproduced ? 0 : 1;
  }
  if (command === 'smoke') {
    const seed = parsed.values.seed ?? 'ogvcs-benchmark-smoke-v1'; let workspace = parsed.values.workspace && resolve(parsed.values.workspace); let temporary = false;
    if (!workspace) { workspace = await mkdtemp(join(tmpdir(), 'ogvcs-benchmark-workspace-')); temporary = true; }
    const output = resolve(parsed.values.output ?? 'artifacts/benchmark-fault-result');
    try {
      const result = await runReferenceHarness({ contract, workspace, output, seed, harnessProfile: parsed.values.profile ?? 'local-smoke', iterations: number(parsed.values.iterations, '--iterations'), operator: parsed.values.operator, classification: parsed.values.classification, command: `ogvcs-benchmark smoke --profile ${parsed.values.profile ?? 'local-smoke'} --seed ${seed}` });
      await machineWrite(undefined, { schemaVersion: 'ogvcs.benchmark/cli-result/v1', command: 'smoke', output, contractManifestSha256: contract.manifestSha256, samples: result.matrix.samples.length, conformancePassed: result.conformance.passed, conformanceFailed: result.conformance.failed, status: result.publication.result.overallStatus, bundleDigest: result.written.manifest.bundleDigest });
      return result.publication.result.overallStatus === 'passed' && result.conformance.failed === 0 ? 0 : 1;
    } finally { if (temporary) await rm(workspace, { recursive: true, force: true }); }
  }
  throw new Error(`unknown command: ${command}`);
}

export async function main(argv) {
  try { process.exitCode = await runCli(argv); }
  catch (error) { const failure = asHarnessError(error, 'HARNESS_INPUT_INVALID'); process.stderr.write(`${canonicalJson({ ok: false, code: failure.code, message: failure.message })}\n`); process.exitCode = 2; }
}
