#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';

import { normalizeNpmTarball } from './normalize-npm-tarball.mjs';

const REPOSITORY = resolve(import.meta.dirname, '..');
const SPEC = join(REPOSITORY, 'spec/authorization/v1');
const RUNTIME = join(REPOSITORY, 'core/authz-contract/js');
const NPM_CLI = process.env.npm_execpath ?? (process.platform === 'win32' ? join(dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js') : null);

function usage() {
  throw new Error('usage: node tools/run-packed-authorization-conformance.mjs --output <directory>');
}

const args = process.argv.slice(2);
if (args.length !== 2 || args[0] !== '--output' || !args[1]) usage();
const output = resolve(args[1]);

function run(command, commandArgs, options = {}) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, commandArgs, { cwd: options.cwd, env: options.env ?? process.env, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    const stdout = [];
    const stderr = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    child.stdout.on('data', (chunk) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes > 64 * 1024 * 1024) child.kill('SIGKILL');
      else stdout.push(chunk);
    });
    child.stderr.on('data', (chunk) => {
      stderrBytes += chunk.length;
      if (stderrBytes > 8 * 1024 * 1024) child.kill('SIGKILL');
      else stderr.push(chunk);
    });
    child.once('error', reject);
    child.once('close', (code, signal) => resolvePromise({ code, signal, stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8') }));
  });
}

function npm(commandArgs, options) {
  return NPM_CLI ? run(process.execPath, [NPM_CLI, ...commandArgs], options) : run('npm', commandArgs, options);
}

async function sha256(path) {
  return createHash('sha256').update(await readFile(path)).digest('hex');
}

const scratch = await mkdtemp(join(tmpdir(), 'ogvcs-authz-packed-'));
try {
  await mkdir(output, { recursive: true });
  const packages = join(output, 'packages');
  const consumer = join(scratch, 'consumer');
  const cache = join(scratch, 'npm-cache');
  await mkdir(packages, { recursive: true });
  await mkdir(consumer);
  const environment = { ...process.env, npm_config_cache: cache, npm_config_audit: 'false', npm_config_fund: 'false' };
  const specPack = await npm(['pack', SPEC, '--json', '--pack-destination', packages], { cwd: REPOSITORY, env: environment });
  if (specPack.code !== 0) throw new Error('cannot pack authorization contract specification');
  const [specResult] = JSON.parse(specPack.stdout);
  const runtimePack = await npm(['pack', RUNTIME, '--json', '--pack-destination', packages], { cwd: REPOSITORY, env: environment });
  if (runtimePack.code !== 0) throw new Error('cannot pack authorization contract runtime');
  const [runtimeResult] = JSON.parse(runtimePack.stdout);
  const specTarball = join(packages, basename(specResult.filename));
  const runtimeTarball = join(packages, basename(runtimeResult.filename));
  await normalizeNpmTarball(specTarball);
  await normalizeNpmTarball(runtimeTarball, { executables: ['package/bin/ogvcs-authz.mjs'] });
  await writeFile(join(consumer, 'package.json'), '{"private":true,"type":"module"}\n');
  const installed = await npm([
    'install', '--offline', '--ignore-scripts', '--no-audit', '--no-fund', '--package-lock=false', specTarball, runtimeTarball,
  ], { cwd: consumer, env: environment });
  if (installed.code !== 0) throw new Error('cannot install packed authorization artifacts offline');
  const runtimeRoot = join(consumer, 'node_modules/@opengamevcs/authorization-contract');
  const cli = join(runtimeRoot, 'bin/ogvcs-authz.mjs');
  const referencePath = join(output, 'reference-report.json');
  const reference = await run(process.execPath, [cli, 'run', '--output', referencePath], { cwd: consumer, env: { ...environment, npm_config_offline: 'true' } });
  if (reference.code !== 0) throw new Error('packed reference conformance failed');
  const externalPath = join(output, 'external-adapter-report.json');
  const external = await run(process.execPath, [
    cli, 'run', '--adapter', process.execPath, '--adapter-arg', join(runtimeRoot, 'examples/external-adapter.mjs'), '--output', externalPath,
  ], { cwd: consumer, env: { ...environment, npm_config_offline: 'true' } });
  if (external.code !== 0) throw new Error('packed external-adapter conformance failed');
  const referenceReport = JSON.parse(await readFile(referencePath, 'utf8'));
  const externalReport = JSON.parse(await readFile(externalPath, 'utf8'));
  if (referenceReport.failed !== 0 || externalReport.failed !== 0 || referenceReport.resultsSha256 !== externalReport.resultsSha256) throw new Error('packed reports disagree');
  const evidence = {
    schemaVersion: 'ogvcs.authorization/packed-evidence/v1',
    contractVersion: referenceReport.contractVersion,
    manifestSha256: referenceReport.manifestSha256,
    registrySetSha256: referenceReport.registrySetSha256,
    resultsSha256: referenceReport.resultsSha256,
    packages: [
      { name: specResult.name, version: specResult.version, filename: basename(specTarball), sha256: await sha256(specTarball) },
      { name: runtimeResult.name, version: runtimeResult.version, filename: basename(runtimeTarball), sha256: await sha256(runtimeTarball) },
    ],
    reports: [
      { adapter: referenceReport.adapter, filename: basename(referencePath), sha256: await sha256(referencePath) },
      { adapter: externalReport.adapter, filename: basename(externalPath), sha256: await sha256(externalPath) },
    ],
  };
  await writeFile(join(output, 'packed-evidence.json'), `${JSON.stringify(evidence)}\n`, 'utf8');
  process.stdout.write(`${JSON.stringify(evidence)}\n`);
} finally {
  await rm(scratch, { recursive: true, force: true, maxRetries: 8, retryDelay: 100 });
}
