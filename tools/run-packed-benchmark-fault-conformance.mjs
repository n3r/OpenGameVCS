#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { parseArgs } from 'node:util';

import { normalizeNpmTarball } from './normalize-npm-tarball.mjs';

const REPOSITORY = resolve(import.meta.dirname, '..');
const PACKAGE_ROOTS = [
  'spec/benchmark-fault/v1', 'foundation/fixture-generator', 'spec/authorization/v1', 'core/authz-contract/js',
  'spec/path-filesystem/v1', 'core/paths-filesystem/js', 'spec/protocols/v1', 'foundation/protocol-baseline/bindings/typescript',
  'foundation/protocol-baseline/js', 'foundation/benchmark-fault-harness',
];
const NPM_CLI = process.env.npm_execpath ?? (process.platform === 'win32' ? join(dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js') : null);

function canonical(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string' || Number.isSafeInteger(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
}
function digest(bytes) { return createHash('sha256').update(bytes).digest('hex'); }
function run(command, args, options = {}) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, args, { cwd: options.cwd, env: options.env ?? process.env, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    const stdout = []; const stderr = []; let stdoutBytes = 0; let stderrBytes = 0;
    child.stdout.on('data', (chunk) => { stdoutBytes += chunk.length; if (stdoutBytes > 16 * 1024 * 1024) child.kill('SIGKILL'); else stdout.push(chunk); });
    child.stderr.on('data', (chunk) => { stderrBytes += chunk.length; if (stderrBytes > 8 * 1024 * 1024) child.kill('SIGKILL'); else stderr.push(chunk); });
    child.once('error', reject);
    child.once('close', (code, signal) => resolvePromise({ code, signal, stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8') }));
  });
}
function npm(args, options) { return NPM_CLI ? run(process.execPath, [NPM_CLI, ...args], options) : run('npm', args, options); }
async function requireSuccess(result, label) { if (result.code !== 0 || result.signal !== null) throw new Error(`${label} failed: ${result.stderr}`); return result; }

const parsed = parseArgs({ options: { output: { type: 'string' }, profile: { type: 'string', default: 'local-smoke' } }, strict: true });
if (!parsed.values.output) throw new Error('usage: node tools/run-packed-benchmark-fault-conformance.mjs --output <directory> [--profile <name>]');
const output = resolve(parsed.values.output);
const scratch = await mkdtemp(join(tmpdir(), 'ogvcs-benchmark-packed-'));
try {
  const packagesDirectory = join(output, 'packages'); const consumer = join(scratch, 'consumer'); const cache = join(scratch, 'npm-cache');
  await mkdir(packagesDirectory, { recursive: true }); await mkdir(consumer);
  const environment = { ...process.env, npm_config_cache: cache, npm_config_audit: 'false', npm_config_fund: 'false', npm_config_offline: 'true' };
  const archives = [];
  for (const relative of PACKAGE_ROOTS) {
    const packageRoot = join(REPOSITORY, relative); const packageJson = JSON.parse(await readFile(join(packageRoot, 'package.json'), 'utf8'));
    const packed = await requireSuccess(await npm(['pack', packageRoot, '--json', '--ignore-scripts', '--pack-destination', packagesDirectory], { cwd: REPOSITORY, env: environment }), `pack ${packageJson.name}`);
    const results = JSON.parse(packed.stdout); if (!Array.isArray(results) || results.length !== 1) throw new Error(`pack ${packageJson.name} returned an invalid inventory`);
    const archivePath = join(packagesDirectory, basename(results[0].filename));
    const binValues = typeof packageJson.bin === 'string' ? [packageJson.bin] : Object.values(packageJson.bin ?? {});
    await normalizeNpmTarball(archivePath, { executables: binValues.map((path) => `package/${path}`) });
    archives.push({ name: packageJson.name, version: packageJson.version, filename: basename(archivePath), path: archivePath, sha256: digest(await readFile(archivePath)) });
  }
  archives.sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0);
  await writeFile(join(consumer, 'package.json'), '{"private":true,"type":"module"}\n', 'utf8');
  await requireSuccess(await npm(['install', '--offline', '--ignore-scripts', '--no-audit', '--no-fund', '--package-lock=false', ...archives.map(({ path }) => path)], { cwd: consumer, env: environment }), 'offline packed install');
  const runtimeRoot = join(consumer, 'node_modules/@opengamevcs/benchmark-fault-harness');
  await requireSuccess(await run(process.execPath, [join(runtimeRoot, 'bin/ogvcs-benchmark.mjs'), 'plan'], { cwd: consumer, env: environment }), 'packed CLI plan');
  const reportDirectory = join(output, 'report');
  await requireSuccess(await run(process.execPath, [join(runtimeRoot, 'scripts/run-ci-report.mjs'), '--output', reportDirectory, '--profile', parsed.values.profile], { cwd: consumer, env: environment }), 'packed retained report');
  const reportBytes = await readFile(join(reportDirectory, 'report.json')); const report = JSON.parse(reportBytes);
  if (report.overallStatus !== 'passed' || report.results.conformanceFailed !== 0 || report.results.faultFailures !== 0 || report.results.brokenMisses !== 0 || report.results.securityMisses !== 0 || report.exactScaleExecuted !== false) throw new Error('packed retained report is not green and bounded');
  const packageSet = archives.map(({ name, version, sha256 }) => ({ name, version, sha256 }));
  const body = {
    schemaVersion: 'ogvcs.benchmark/packed-evidence/v1', contractManifestSha256: report.contractManifestSha256,
    profile: report.profile, semanticResultsSha256: report.semanticResultsSha256, packageSetSha256: digest(canonical(packageSet)),
    packages: archives.map(({ path: _path, ...entry }) => entry), report: { path: 'report/report.json', sha256: digest(reportBytes), reportSha256: report.reportSha256 },
    platform: { os: process.platform, architecture: process.arch, node: process.versions.node }, exactScaleExecuted: false,
  };
  const evidence = { ...body, evidenceSha256: digest(canonical(body)) };
  await writeFile(join(output, 'packed-evidence.json'), `${canonical(evidence)}\n`, { encoding: 'utf8', flag: 'wx' });
  process.stdout.write(`${canonical(evidence)}\n`);
} finally { await rm(scratch, { recursive: true, force: true, maxRetries: 8, retryDelay: 50 }); }
