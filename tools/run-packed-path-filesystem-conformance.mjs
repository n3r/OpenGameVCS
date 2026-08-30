#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';

import { normalizeNpmTarball } from './normalize-npm-tarball.mjs';

const REPOSITORY = resolve(import.meta.dirname, '..');
const SPEC = join(REPOSITORY, 'spec/path-filesystem/v1');
const RUNTIME = join(REPOSITORY, 'core/paths-filesystem/js');
const NPM_CLI = process.env.npm_execpath ?? (process.platform === 'win32' ? join(dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js') : null);
const args = process.argv.slice(2);
if (args.length !== 2 || args[0] !== '--output' || !args[1]) throw new Error('usage: node tools/run-packed-path-filesystem-conformance.mjs --output <directory>');
const output = resolve(args[1]);

function run(command, commandArgs, options = {}) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, commandArgs, { cwd: options.cwd, env: options.env ?? process.env, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    const stdout = []; const stderr = []; let stdoutBytes = 0; let stderrBytes = 0;
    child.stdout.on('data', (chunk) => { stdoutBytes += chunk.length; if (stdoutBytes > 16 * 1024 * 1024) child.kill('SIGKILL'); else stdout.push(chunk); });
    child.stderr.on('data', (chunk) => { stderrBytes += chunk.length; if (stderrBytes > 8 * 1024 * 1024) child.kill('SIGKILL'); else stderr.push(chunk); });
    child.once('error', reject);
    child.once('close', (code, signal) => resolvePromise({ code, signal, stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8') }));
  });
}
function npm(commandArgs, options) { return NPM_CLI ? run(process.execPath, [NPM_CLI, ...commandArgs], options) : run('npm', commandArgs, options); }
async function fileSha256(path) { return createHash('sha256').update(await readFile(path)).digest('hex'); }
function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string' || Number.isSafeInteger(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}

const scratch = await mkdtemp(join(tmpdir(), 'ogvcs-path-packed-'));
try {
  const packages = join(output, 'packages'); const consumer = join(scratch, 'consumer');
  await mkdir(output, { recursive: true }); await mkdir(packages, { recursive: true }); await mkdir(consumer);
  const environment = { ...process.env, npm_config_cache: join(scratch, 'npm-cache'), npm_config_audit: 'false', npm_config_fund: 'false' };
  const specPack = await npm(['pack', SPEC, '--json', '--pack-destination', packages], { cwd: REPOSITORY, env: environment });
  if (specPack.code !== 0) throw new Error(`cannot pack path contract: ${specPack.stderr}`);
  const runtimePack = await npm(['pack', RUNTIME, '--json', '--pack-destination', packages], { cwd: REPOSITORY, env: environment });
  if (runtimePack.code !== 0) throw new Error(`cannot pack path runtime: ${runtimePack.stderr}`);
  const [specResult] = JSON.parse(specPack.stdout); const [runtimeResult] = JSON.parse(runtimePack.stdout);
  const specTarball = join(packages, basename(specResult.filename)); const runtimeTarball = join(packages, basename(runtimeResult.filename));
  await normalizeNpmTarball(specTarball);
  await normalizeNpmTarball(runtimeTarball, { executables: ['package/bin/ogvcs-path.mjs'] });
  await writeFile(join(consumer, 'package.json'), '{"private":true,"type":"module"}\n');
  const install = await npm(['install', '--offline', '--ignore-scripts', '--no-audit', '--no-fund', '--package-lock=false', specTarball, runtimeTarball], { cwd: consumer, env: environment });
  if (install.code !== 0) throw new Error(`cannot install packed path artifacts offline: ${install.stderr}`);
  const runtimeRoot = join(consumer, 'node_modules/@opengamevcs/path-filesystem');
  const cli = join(runtimeRoot, 'bin/ogvcs-path.mjs');
  const reportPath = join(output, 'conformance-report.json');
  const execution = await run(process.execPath, [cli, 'conformance', '--output', reportPath], { cwd: consumer, env: { ...environment, npm_config_offline: 'true' } });
  if (execution.code !== 0) throw new Error(`packed path conformance failed: ${execution.stderr}`);
  const report = JSON.parse(await readFile(reportPath));
  if (report.total !== 79 || report.passed !== 79 || report.failed !== 0) throw new Error('packed path report does not pass every bounded case');
  if (report.implementation?.name !== '@opengamevcs/path-filesystem' || report.implementation?.version !== '1.1.0') throw new Error('packed path report has the wrong implementation identity');
  if (report.results?.find(({ id }) => id === 'native:bounded-staged-stream-publication')?.passed !== true) throw new Error('packed path report omits bounded staged stream publication');
  const evidence = {
    schemaVersion: 'ogvcs.path/packed-evidence/v1', contractVersion: report.contractVersion,
    manifestSha256: report.manifestSha256, registrySetSha256: report.registrySetSha256,
    unicodeCaseFoldingSha256: report.unicodeCaseFoldingSha256, resultsSha256: report.resultsSha256,
    platform: report.platform,
    packages: [
      { name: specResult.name, version: specResult.version, filename: basename(specTarball), sha256: await fileSha256(specTarball) },
      { name: runtimeResult.name, version: runtimeResult.version, filename: basename(runtimeTarball), sha256: await fileSha256(runtimeTarball) },
    ],
    report: { filename: basename(reportPath), sha256: await fileSha256(reportPath) },
  };
  await writeFile(join(output, 'packed-evidence.json'), `${canonicalJson(evidence)}\n`, 'utf8');
  process.stdout.write(`${JSON.stringify(evidence)}\n`);
} finally { await rm(scratch, { recursive: true, force: true, maxRetries: 8, retryDelay: 50 }); }
