#!/usr/bin/env node

import { mkdir, rename, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';

import { canonicalJson } from '../src/canonical.mjs';
import { loadAuthorizationContract } from '../src/contract.mjs';
import { asContractError, ERROR_CODES } from '../src/errors.mjs';
import { verifyTransferGrant } from '../src/grants.mjs';
import { runThreatVectors } from '../src/runner.mjs';

const HELP = `OpenGameVCS authorization contract runner\n\nUsage:\n  ogvcs-authz run [--adapter <command>] [--adapter-arg <argument>]... [--output <report.json>]\n  ogvcs-authz inspect\n  ogvcs-authz verify-grants\n  ogvcs-authz --help\n`;

async function atomicJson(path, value) {
  const destination = resolve(path);
  await mkdir(dirname(destination), { recursive: true });
  const temporary = `${destination}.tmp-${process.pid}-${Date.now()}`;
  await writeFile(temporary, `${canonicalJson(value)}\n`, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
  await rename(temporary, destination);
}

function runOptions(args) {
  const options = {};
  const adapter = [];
  for (let index = 0; index < args.length; index += 1) {
    if (args[index] === '--output' && args[index + 1]) options.output = args[++index];
    else if (args[index] === '--adapter' && args[index + 1]) adapter.push(args[++index]);
    else if (args[index] === '--adapter-arg' && args[index + 1] && adapter.length > 0) adapter.push(args[++index]);
    else throw new TypeError(`unknown or incomplete option: ${args[index]}`);
  }
  if (adapter.length > 0) options.adapter = adapter;
  return options;
}

async function main() {
  const [command, ...args] = process.argv.slice(2);
  if (command === undefined || command === '--help' || command === '-h') {
    process.stdout.write(HELP);
    return 0;
  }
  if (command === 'inspect' && args.length === 0) {
    const contract = await loadAuthorizationContract();
    process.stdout.write(`${canonicalJson({
      schemaVersion: 'ogvcs.authorization/inspect-result/v1',
      contractVersion: contract.manifest.contractVersion,
      manifestSha256: contract.manifestSha256,
      registrySetSha256: contract.manifest.registrySetSha256,
      registries: Object.keys(contract.registries).length,
      permissions: contract.registries.permissions.entries.length,
      resources: contract.registries.resources.entries.length,
      threats: contract.registries.threats.entries.length,
      abuseVectors: contract.vectors.abuseCatalog.cases.length,
    })}\n`);
    return 0;
  }
  if (command === 'verify-grants' && args.length === 0) {
    const contract = await loadAuthorizationContract();
    const vector = contract.vectors.grants;
    const rows = vector.cases.map((testCase) => {
      const actual = verifyTransferGrant(testCase.envelope, testCase.context, vector.key.publicJwk);
      return { id: testCase.id, status: actual.result === testCase.expected.result && actual.code === testCase.expected.code ? 'passed' : 'failed', code: actual.code };
    });
    const failed = rows.filter(({ status }) => status === 'failed').length;
    process.stdout.write(`${canonicalJson({ schemaVersion: 'ogvcs.authorization/grant-report/v1', cases: rows.length, passed: rows.length - failed, failed, rows })}\n`);
    return failed === 0 ? 0 : 1;
  }
  if (command === 'run') {
    const options = runOptions(args);
    const report = await runThreatVectors(options);
    if (options.output) await atomicJson(options.output, report);
    process.stdout.write(`${canonicalJson(report)}\n`);
    return report.failed === 0 ? 0 : 1;
  }
  throw new TypeError(`unknown command: ${command}`);
}

try {
  process.exitCode = await main();
} catch (error) {
  const failure = asContractError(error, error instanceof TypeError ? ERROR_CODES.INPUT_INVALID : undefined, 'authorization runner failed');
  process.stderr.write(`${canonicalJson({ ok: false, error: failure.toJSON() })}\n`);
  process.exitCode = failure.exitCode;
}
