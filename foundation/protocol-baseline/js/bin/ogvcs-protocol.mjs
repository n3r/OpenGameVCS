#!/usr/bin/env node

import { mkdir, open, rename, unlink } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';

import { canonicalBytes, canonicalJson } from '../src/canonical.mjs';
import { loadProtocolContract } from '../src/contract.mjs';
import { asProtocolError, RUNTIME_ERROR_CODES } from '../src/errors.mjs';
import { HARD_LIMITS } from '../src/limits.mjs';
import { runExternalProtocolConformance, runReferenceProtocolConformance } from '../src/runner.mjs';

const HELP = `OpenGameVCS protocol baseline runtime\n\nUsage:\n  ogvcs-protocol inspect [--contract <root>]\n  ogvcs-protocol run [--contract <root>] [--output <report.json>] [--adapter <command> [--adapter-arg <argument>]...] [--node-adapter-read-root <absolute-root>]... [--expected-adapter-id <id>] [--timeout-ms <milliseconds>] [--max-cases <count>]\n  ogvcs-protocol --help\n\nThe default run uses the reference JavaScript evaluator. External adapters receive only canonical RunnerCase JSONL; oracle outcomes remain in the harness.\n`;

function takeOnce(options, name, value) {
  if (Object.hasOwn(options, name)) throw new TypeError(`duplicate option: --${name}`);
  options[name] = value;
}

function positiveInteger(value, label, maximum) {
  if (typeof value !== 'string' || !/^[1-9][0-9]*$/u.test(value)) throw new TypeError(`${label} must be a positive integer`);
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number > maximum) throw new TypeError(`${label} exceeds its supported maximum`);
  return number;
}

function parseOptions(args, run) {
  const options = {};
  const adapter = [];
  const nodeAdapterReadRoots = [];
  for (let index = 0; index < args.length; index += 1) {
    const name = args[index];
    const value = args[index + 1];
    if (name === '--contract' && value !== undefined) { takeOnce(options, 'contract', value); index += 1; }
    else if (run && name === '--output' && value !== undefined) { takeOnce(options, 'output', value); index += 1; }
    else if (run && name === '--adapter' && value !== undefined && adapter.length === 0) { adapter.push(value); index += 1; }
    else if (run && name === '--adapter-arg' && value !== undefined && adapter.length > 0) { adapter.push(value); index += 1; }
    else if (run && name === '--node-adapter-read-root' && value !== undefined && adapter.length > 0) { nodeAdapterReadRoots.push(value); index += 1; }
    else if (run && name === '--expected-adapter-id' && value !== undefined) { takeOnce(options, 'expectedAdapterId', value); index += 1; }
    else if (run && name === '--timeout-ms' && value !== undefined) { takeOnce(options, 'timeoutMs', positiveInteger(value, 'timeout-ms', HARD_LIMITS.timeoutMs)); index += 1; }
    else if (run && name === '--max-cases' && value !== undefined) { takeOnce(options, 'maxCases', positiveInteger(value, 'max-cases', HARD_LIMITS.adapterCases)); index += 1; }
    else throw new TypeError(`unknown, duplicate, or incomplete option: ${name}`);
  }
  if (options.contract !== undefined && (options.contract.length === 0 || options.contract.length > 16_384 || options.contract.includes('\0'))) throw new TypeError('contract path is invalid');
  if (options.output !== undefined && (options.output.length === 0 || options.output.length > 16_384 || options.output.includes('\0'))) throw new TypeError('output path is invalid');
  if (options.expectedAdapterId !== undefined && adapter.length === 0) throw new TypeError('--expected-adapter-id requires --adapter');
  if (adapter.length > 0) options.adapter = adapter;
  if (nodeAdapterReadRoots.length > 0) options.nodeAdapterReadRoots = nodeAdapterReadRoots;
  return options;
}

async function writeAtomic(path, value) {
  const destination = resolve(path);
  await mkdir(dirname(destination), { recursive: true });
  const temporary = `${destination}.tmp-${process.pid}-${Date.now()}`;
  let handle;
  try {
    handle = await open(temporary, 'wx', 0o600);
    await handle.writeFile(Buffer.concat([canonicalBytes(value), Buffer.from('\n')]));
    await handle.sync();
    await handle.close();
    handle = undefined;
    await rename(temporary, destination);
  } catch (error) {
    await handle?.close().catch(() => {});
    await unlink(temporary).catch(() => {});
    throw error;
  }
}

async function main() {
  const [command, ...args] = process.argv.slice(2);
  if (command === undefined || command === '--help' || command === '-h') {
    if (args.length > 0) throw new TypeError('help takes no options');
    process.stdout.write(HELP);
    return 0;
  }
  if (command === 'inspect') {
    const options = parseOptions(args, false);
    const contract = await loadProtocolContract({ ...(options.contract === undefined ? {} : { root: options.contract }), cache: false });
    process.stdout.write(`${canonicalJson({
      schemaVersion: 'ogvcs.protocol/inspect-result/v1',
      contractVersion: contract.manifest.contractVersion,
      contractManifestSha256: contract.manifestSha256,
      registrySetSha256: contract.manifest.registrySetSha256,
      schemaSetSha256: contract.manifest.schemaSetSha256,
      vectorSetSha256: contract.manifest.vectorSetSha256,
      artifacts: contract.manifest.counts.artifacts,
      schemas: contract.manifest.counts.schemas,
      registries: contract.manifest.counts.registries,
      scenarios: contract.manifest.counts.scenarios,
    })}\n`);
    return 0;
  }
  if (command === 'run') {
    const options = parseOptions(args, true);
    const contract = await loadProtocolContract({ ...(options.contract === undefined ? {} : { root: options.contract }), cache: false, timeoutMs: options.timeoutMs });
    const runOptions = {
      timeoutMs: options.timeoutMs,
      maxCases: options.maxCases,
      expectedAdapterId: options.expectedAdapterId,
      nodeAdapterReadRoots: options.nodeAdapterReadRoots,
    };
    const report = options.adapter === undefined
      ? await runReferenceProtocolConformance(contract, runOptions)
      : await runExternalProtocolConformance(contract, options.adapter, runOptions);
    if (options.output !== undefined) await writeAtomic(options.output, report);
    process.stdout.write(`${canonicalJson(report)}\n`);
    return report.failed === 0 ? 0 : 1;
  }
  throw new TypeError(`unknown command: ${command}`);
}

try { process.exitCode = await main(); } catch (error) {
  const failure = asProtocolError(error, error instanceof TypeError ? RUNTIME_ERROR_CODES.INPUT_INVALID : undefined, 'protocol baseline command failed');
  process.stderr.write(`${canonicalJson({ ok: false, error: failure.toJSON() })}\n`);
  process.exitCode = failure.exitCode;
}
