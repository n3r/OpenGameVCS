#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { copyFile, lstat, mkdir, mkdtemp, open, readFile, rename, rm, unlink, writeFile } from 'node:fs/promises';
import { platform, tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

import { normalizeNpmTarball } from './normalize-npm-tarball.mjs';

const REPOSITORY = resolve(import.meta.dirname, '..');
const ROOT_LICENSE = join(REPOSITORY, 'LICENSE');
const SOURCES = Object.freeze({
  authorization: join(REPOSITORY, 'spec/authorization/v1'),
  authorizationRuntime: join(REPOSITORY, 'core/authz-contract/js'),
  contract: join(REPOSITORY, 'spec/protocols/v1'),
  runtime: join(REPOSITORY, 'foundation/protocol-baseline/js'),
  independent: join(REPOSITORY, 'foundation/protocol-baseline/adapters/js-independent'),
  typescript: join(REPOSITORY, 'foundation/protocol-baseline/bindings/typescript'),
});
const PACKAGE_VERSIONS = new Map([
  ['@opengamevcs/authorization-contract', '1.0.0'],
  ['@opengamevcs/authorization-contract-v1', '1.0.0'],
  ['@opengamevcs/protocol-baseline', '1.0.0-rc.1'],
  ['@opengamevcs/protocol-baseline-independent-adapter', '1.0.0-rc.1'],
  ['@opengamevcs/protocol-contract-v1', '1.0.0-rc.1'],
  ['@opengamevcs/protocol-types-v1', '1.0.0-rc.1'],
]);
const CODEGEN_FILES = Object.freeze([
  'foundation/protocol-baseline/codegen/LICENSE',
  'foundation/protocol-baseline/codegen/README.md',
]);
const AUTHORIZATION_RUNTIME_SOURCE_FILES = Object.freeze([
  'core/authz-contract/js/LICENSE',
  'core/authz-contract/js/package.json',
  'core/authz-contract/js/src/canonical.mjs',
  'core/authz-contract/js/src/contract.mjs',
  'core/authz-contract/js/src/errors.mjs',
  'core/authz-contract/js/src/evaluator.mjs',
  'core/authz-contract/js/src/fixture-bridge.mjs',
  'core/authz-contract/js/src/generated.mjs',
  'core/authz-contract/js/src/grants.mjs',
  'core/authz-contract/js/src/index.mjs',
  'core/authz-contract/js/src/runner.mjs',
  'core/authz-contract/js/src/sandbox.mjs',
  'core/authz-contract/js/src/validate.mjs',
  'core/authz-contract/js/src/view.mjs',
]);
const CONTRACT_CHECK_FILES = Object.freeze([
  'spec/protocols/v1/validate-spec.mjs',
  'spec/protocols/v1/test/package-contract.test.mjs',
  'spec/protocols/v1/test/validate-spec.test.mjs',
]);
const NPM_CLI = process.env.npm_execpath
  ?? (process.platform === 'win32' ? join(dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js') : null);
const MAX_STDOUT = 32 * 1024 * 1024;
const MAX_STDERR = 8 * 1024 * 1024;

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string' || Number.isSafeInteger(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  throw new TypeError('evidence contains a noncanonical value');
}

function hostPlatform() {
  return { linux: 'linux', darwin: 'macos', win32: 'windows' }[platform()] ?? platform();
}

function parseArguments(args) {
  if (args.length !== 2 || args[0] !== '--output' || !args[1] || args[1].includes('\0')) {
    throw new Error('usage: node tools/run-packed-protocol-conformance.mjs --output <directory>');
  }
  return resolve(args[1]);
}

function safeRelativePath(value, label) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 16_384 || value.includes('\\') || value.startsWith('/') || value.split('/').some((part) => part === '' || part === '.' || part === '..')) {
    throw new Error(`${label} is not a safe relative path`);
  }
  return value;
}

function run(command, args, options = {}) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env ?? process.env,
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });
    const stdout = [];
    const stderr = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let overflow = false;
    child.stdout.on('data', (chunk) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes > (options.maxStdout ?? MAX_STDOUT)) { overflow = true; child.kill('SIGKILL'); } else stdout.push(chunk);
    });
    child.stderr.on('data', (chunk) => {
      stderrBytes += chunk.length;
      if (stderrBytes > (options.maxStderr ?? MAX_STDERR)) { overflow = true; child.kill('SIGKILL'); } else stderr.push(chunk);
    });
    child.once('error', reject);
    child.once('close', (code, signal) => resolvePromise({
      code,
      signal,
      overflow,
      stdout: Buffer.concat(stdout).toString('utf8'),
      stderr: Buffer.concat(stderr).toString('utf8'),
    }));
  });
}

function npm(args, options) {
  return NPM_CLI ? run(process.execPath, [NPM_CLI, ...args], options) : run('npm', args, options);
}

async function expectSuccess(result, label) {
  if (result.code !== 0 || result.signal !== null || result.overflow) {
    throw new Error(`${label} failed: ${result.stderr.slice(0, 4096)}`);
  }
  return result;
}

async function expectAbsent(path, label) {
  try {
    await lstat(path);
  } catch (error) {
    if (error?.code === 'ENOENT') return;
    throw error;
  }
  throw new Error(`${label} is present in the isolated adapter closure`);
}

async function writeCanonical(path, value) {
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.tmp-${process.pid}-${Date.now()}`;
  let handle;
  try {
    handle = await open(temporary, 'wx', 0o600);
    await handle.writeFile(`${canonicalJson(value)}\n`, 'utf8');
    await handle.sync();
    await handle.close();
    handle = undefined;
    await rename(temporary, path);
  } catch (error) {
    await handle?.close().catch(() => {});
    await unlink(temporary).catch(() => {});
    throw error;
  }
}

async function buildOfflineSource(output, environment) {
  const destination = join(output, 'offline-source');
  const rootLicenseSha256 = sha256(await readFile(ROOT_LICENSE));
  const contractManifest = JSON.parse(await readFile(join(REPOSITORY, 'spec/protocols/v1/manifest.json')));
  const bindingManifest = JSON.parse(await readFile(join(REPOSITORY, 'foundation/protocol-baseline/bindings/manifest.json')));
  if (!Array.isArray(contractManifest.artifacts) || !Array.isArray(contractManifest.generatorInputs) || !Array.isArray(contractManifest.generatorSources) || !Array.isArray(bindingManifest.artifacts)) throw new Error('generated manifests do not declare their source files');
  if (contractManifest.artifacts.length > 4096 || contractManifest.generatorInputs.length > 64 || contractManifest.generatorSources.length > 64 || bindingManifest.artifacts.length > 4096) throw new Error('generated manifest inventory exceeds the offline-source ceiling');
  const declared = new Map();
  const declaredBytes = new Map();
  const declare = (relativePath, expectedSha256, label) => {
    safeRelativePath(relativePath, label);
    if (expectedSha256 !== undefined && !/^[0-9a-f]{64}$/u.test(expectedSha256)) throw new Error(`${label} has an invalid SHA-256`);
    if (declared.has(relativePath)) throw new Error(`${label} is duplicated: ${relativePath}`);
    declared.set(relativePath, expectedSha256);
  };
  for (const path of CODEGEN_FILES) declare(path, undefined, 'offline code-generator file');
  for (const path of AUTHORIZATION_RUNTIME_SOURCE_FILES) declare(path, undefined, 'offline authorization-runtime source');
  for (const source of contractManifest.generatorSources) {
    if (typeof source?.path !== 'string' || basename(source.path) !== source.path || !/^[A-Za-z0-9._-]+$/u.test(source.path) || !/^[0-9a-f]{64}$/u.test(source.sha256)) throw new Error('contract manifest contains an unsafe generator source');
    declare(`foundation/protocol-baseline/codegen/${source.path}`, source.sha256, 'contract generator source');
  }
  for (const input of contractManifest.generatorInputs) {
    safeRelativePath(input?.path, 'contract generator input path');
    if (!Number.isSafeInteger(input.bytes) || input.bytes <= 0 || input.bytes > 16 * 1024 * 1024 || typeof input.role !== 'string' || !/^[a-z][a-z0-9-]{0,127}$/u.test(input.role)) throw new Error('contract manifest contains an invalid generator input');
    declare(input.path, input.sha256, 'contract generator input');
    declaredBytes.set(input.path, input.bytes);
  }
  for (const path of CONTRACT_CHECK_FILES) declare(path, undefined, 'contract validation source');
  // LICENSE, README.md, and package.json are authenticated contract artifacts.
  // Only the self-authenticating manifest and its separately bound execution
  // view live outside that artifact inventory.
  for (const path of ['adapter-execution-view.json', 'manifest.json']) declare(`spec/protocols/v1/${path}`, undefined, 'contract support file');
  for (const record of contractManifest.artifacts) {
    safeRelativePath(record?.path, 'contract artifact path');
    declare(`spec/protocols/v1/${record.path}`, record.sha256, 'contract artifact');
  }
  declare('foundation/protocol-baseline/bindings/manifest.json', undefined, 'binding manifest');
  for (const record of bindingManifest.artifacts) {
    safeRelativePath(record?.path, 'binding artifact path');
    declare(`foundation/protocol-baseline/bindings/${record.path}`, record.sha256, 'binding artifact');
  }
  const entries = [];
  for (const [relativePath, expectedSha256] of [...declared].sort(([left], [right]) => left.localeCompare(right))) {
    const source = join(REPOSITORY, relativePath);
    const target = join(destination, relativePath);
    const metadata = await lstat(source);
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > 16 * 1024 * 1024) throw new Error(`offline source is not a bounded regular file: ${relativePath}`);
    await mkdir(dirname(target), { recursive: true });
    await copyFile(source, target);
    const bytes = await readFile(target);
    const digest = sha256(bytes);
    if (expectedSha256 !== undefined && digest !== expectedSha256) throw new Error(`declared generated source digest differs: ${relativePath}`);
    if (declaredBytes.has(relativePath) && bytes.length !== declaredBytes.get(relativePath)) throw new Error(`declared generated source length differs: ${relativePath}`);
    if (basename(relativePath) === 'LICENSE' && digest !== rootLicenseSha256) throw new Error(`offline source license differs: ${relativePath}`);
    entries.push({ path: relativePath, bytes: bytes.length, sha256: digest });
  }
  entries.sort((left, right) => left.path.localeCompare(right.path));
  const manifest = {
    schemaVersion: 'ogvcs.protocol/offline-source-manifest/v1',
    license: 'MIT',
    files: entries,
    sourceSetSha256: sha256(Buffer.from(canonicalJson(entries), 'utf8')),
  };
  await writeCanonical(join(destination, 'offline-source-manifest.json'), manifest);
  await expectSuccess(await run(process.execPath, [
    join(destination, 'foundation/protocol-baseline/codegen/generate.mjs'),
    '--check',
  ], { cwd: destination, env: { ...environment, npm_config_offline: 'true' } }), 'offline source regeneration check');
  await expectSuccess(await npm([
    '--prefix', join(destination, 'spec/protocols/v1'), 'run', 'check',
  ], { cwd: destination, env: { ...environment, npm_config_offline: 'true' } }), 'offline contract package check');
  await expectSuccess(await npm([
    '--prefix', join(destination, 'spec/protocols/v1'), 'test',
  ], { cwd: destination, env: { ...environment, npm_config_offline: 'true' } }), 'offline contract package tests');
  await expectSuccess(await run(process.execPath, [
    '--test',
    join(destination, 'spec/protocols/v1/test/package-contract.test.mjs'),
    join(destination, 'spec/protocols/v1/test/validate-spec.test.mjs'),
  ], { cwd: destination, env: { ...environment, npm_config_offline: 'true' } }), 'offline contract source tests');
  return manifest;
}

async function pack(name, source, packages, environment, executables = []) {
  const [rootLicense, packageLicense] = await Promise.all([
    readFile(ROOT_LICENSE),
    readFile(join(source, 'LICENSE')),
  ]);
  if (!rootLicense.equals(packageLicense)) throw new Error(`pack ${name} does not carry the repository MIT license`);
  const result = await expectSuccess(await npm(['pack', source, '--json', '--pack-destination', packages], {
    cwd: REPOSITORY,
    env: environment,
  }), `pack ${name}`);
  let records;
  try { records = JSON.parse(result.stdout); } catch (error) { throw new Error(`pack ${name} returned invalid JSON`, { cause: error }); }
  if (!Array.isArray(records) || records.length !== 1 || records[0].name !== name || records[0].version !== PACKAGE_VERSIONS.get(name) || basename(records[0].filename) !== records[0].filename) {
    throw new Error(`pack ${name} returned an unexpected package record`);
  }
  const tarball = join(packages, records[0].filename);
  await normalizeNpmTarball(tarball, { executables });
  if (!records[0].files?.some?.(({ path }) => path === 'LICENSE')) throw new Error(`pack ${name} omits MIT LICENSE`);
  const bytes = await readFile(tarball);
  return { name, version: records[0].version, filename: basename(tarball), bytes: bytes.length, sha256: sha256(bytes), path: tarball };
}

function validateResultRows(results, label) {
  const seen = new Set();
  for (const [index, result] of results.entries()) {
    if (!result || typeof result !== 'object' || Array.isArray(result)) throw new Error(`${label} result ${index} is not an object`);
    const keys = Object.keys(result).sort();
    const expectedKeys = [
      'code', 'id', 'mutationCount', 'preMutation', 'result', 'schemaVersion', 'traceDigest',
      ...(result.semanticDigest === undefined ? [] : ['semanticDigest']),
    ].sort();
    if (keys.length !== expectedKeys.length || keys.some((key, offset) => key !== expectedKeys[offset])) {
      throw new Error(`${label} result ${index} has an invalid field set`);
    }
    if (result.schemaVersion !== 'ogvcs.protocol/runner-result/v1'
        || typeof result.id !== 'string'
        || Buffer.byteLength(result.id, 'utf8') > 256
        || !/^[a-z0-9][a-z0-9._/-]*(?:@[0-9]+)?$/u.test(result.id)
        || seen.has(result.id)
        || !['accept', 'reject'].includes(result.result)
        || !/^[A-Z][A-Z0-9_]{0,63}$/u.test(result.code)
        || (result.result === 'accept') !== (result.code === 'NONE')
        || typeof result.preMutation !== 'boolean'
        || !Number.isSafeInteger(result.mutationCount)
        || result.mutationCount < 0
        || result.preMutation !== (result.mutationCount === 0)
        || !/^[0-9a-f]{64}$/u.test(result.traceDigest)
        || (result.semanticDigest !== undefined && !/^[0-9a-f]{64}$/u.test(result.semanticDigest))) {
      throw new Error(`${label} result ${index} is invalid`);
    }
    seen.add(result.id);
  }
}

function validateRunnerReport(report, manifestSha256, adapterId, scenarios) {
  const keys = report && typeof report === 'object' ? Object.keys(report).sort() : [];
  const expectedKeys = ['adapterId', 'contractManifestSha256', 'failed', 'passed', 'reportDigest', 'results', 'schemaVersion'].sort();
  if (keys.length !== expectedKeys.length
      || keys.some((key, index) => key !== expectedKeys[index])
      || report?.schemaVersion !== 'ogvcs.protocol/runner-report/v1'
      || report.adapterId !== adapterId
      || report.contractManifestSha256 !== manifestSha256
      || report.passed !== scenarios
      || report.failed !== 0
      || !Array.isArray(report.results)
      || report.results.length !== scenarios
      || sha256(Buffer.from(canonicalJson(report.results), 'utf8')) !== report.reportDigest) {
    throw new Error(`packed protocol report is invalid: ${adapterId}`);
  }
  validateResultRows(report.results, adapterId);
}

export async function runPackedProtocolConformance(output) {
  const destination = resolve(output);
  const packages = join(destination, 'packages');
  const scratch = await mkdtemp(join(tmpdir(), 'ogvcs-protocol-packed-'));
  let adapterScratch;
  try {
    adapterScratch = await mkdtemp(join(tmpdir(), 'ogvcs-protocol-adapter-'));
    await mkdir(packages, { recursive: true });
    const environment = {
      ...process.env,
      npm_config_cache: join(scratch, 'npm-cache'),
      npm_config_audit: 'false',
      npm_config_fund: 'false',
      npm_config_offline: 'true',
    };
    const packageRecords = [
      await pack('@opengamevcs/authorization-contract-v1', SOURCES.authorization, packages, environment),
      await pack('@opengamevcs/authorization-contract', SOURCES.authorizationRuntime, packages, environment, ['package/bin/ogvcs-authz.mjs']),
      await pack('@opengamevcs/protocol-contract-v1', SOURCES.contract, packages, environment),
      await pack('@opengamevcs/protocol-baseline', SOURCES.runtime, packages, environment, ['package/bin/ogvcs-protocol.mjs']),
      await pack('@opengamevcs/protocol-baseline-independent-adapter', SOURCES.independent, packages, environment, ['package/bin/ogvcs-protocol-independent-adapter.mjs']),
      await pack('@opengamevcs/protocol-types-v1', SOURCES.typescript, packages, environment),
    ];
    const consumer = join(scratch, 'consumer');
    await mkdir(consumer);
    await writeFile(join(consumer, 'package.json'), '{"private":true,"type":"module"}\n', 'utf8');
    const packagesByName = new Map(packageRecords.map((record) => [record.name, record]));
    const consumerRecords = packageRecords.filter(({ name }) => name !== '@opengamevcs/protocol-baseline-independent-adapter');
    const install = await npm([
      'install', '--offline', '--ignore-scripts', '--no-audit', '--no-fund', '--package-lock=false',
      ...consumerRecords.map(({ path }) => path),
    ], { cwd: consumer, env: environment });
    await expectSuccess(install, 'offline install of packed protocol artifacts');

    const adapterConsumer = join(adapterScratch, 'consumer');
    await mkdir(adapterConsumer);
    await writeFile(join(adapterConsumer, 'package.json'), '{"private":true,"type":"module"}\n', 'utf8');
    const adapterRecords = [
      packagesByName.get('@opengamevcs/authorization-contract-v1'),
      packagesByName.get('@opengamevcs/authorization-contract'),
      packagesByName.get('@opengamevcs/protocol-baseline-independent-adapter'),
    ];
    if (adapterRecords.some((record) => record === undefined)) throw new Error('independent adapter package closure is incomplete');
    await expectSuccess(await npm([
      'install', '--offline', '--ignore-scripts', '--no-audit', '--no-fund', '--package-lock=false',
      ...adapterRecords.map(({ path }) => path),
    ], { cwd: adapterConsumer, env: { ...environment, npm_config_cache: join(adapterScratch, 'npm-cache') } }), 'offline install of isolated independent adapter artifacts');
    const adapterScope = join(adapterConsumer, 'node_modules/@opengamevcs');
    await rm(join(adapterScope, 'authorization-contract-v1'), { recursive: true, force: true, maxRetries: 8, retryDelay: 50 });
    await expectAbsent(join(adapterScope, 'authorization-contract-v1'), 'authorization vector package');
    await expectAbsent(join(adapterScope, 'protocol-contract-v1'), 'protocol vector package');

    const installed = join(consumer, 'node_modules/@opengamevcs');
    const contractRoot = join(installed, 'protocol-contract-v1');
    const runtimeCli = join(installed, 'protocol-baseline/bin/ogvcs-protocol.mjs');
    const independentCli = join(adapterConsumer, 'node_modules/@opengamevcs/protocol-baseline-independent-adapter/bin/ogvcs-protocol-independent-adapter.mjs');
    const referencePath = join(destination, 'reference-report.json');
    const independentPath = join(destination, 'independent-report.json');
    const runEnvironment = { ...environment, npm_config_offline: 'true' };
    await expectSuccess(await npm(['--prefix', contractRoot, 'run', 'check'], {
      cwd: consumer,
      env: runEnvironment,
    }), 'installed contract package check');
    await expectSuccess(await npm(['--prefix', contractRoot, 'test'], {
      cwd: consumer,
      env: runEnvironment,
    }), 'installed contract package test');
    await expectSuccess(await run(process.execPath, [runtimeCli, 'run', '--contract', contractRoot, '--output', referencePath], { cwd: consumer, env: runEnvironment }), 'packed reference adapter');
    await expectSuccess(await run(process.execPath, [
      runtimeCli, 'run', '--contract', contractRoot, '--output', independentPath,
      '--adapter', process.execPath,
      '--adapter-arg', independentCli,
      '--adapter-arg', '--contract',
      '--adapter-arg', contractRoot,
      '--expected-adapter-id', 'ogvcs.protocol/independent-js@1',
      '--node-adapter-read-root', adapterConsumer,
    ], { cwd: consumer, env: runEnvironment }), 'packed independent adapter');

    const contractManifestBytes = await readFile(join(contractRoot, 'manifest.json'));
    const contractManifest = JSON.parse(contractManifestBytes);
    const referenceBytes = await readFile(referencePath);
    const independentBytes = await readFile(independentPath);
    const referenceReport = JSON.parse(referenceBytes);
    const independentReport = JSON.parse(independentBytes);
    const contractManifestSha256 = sha256(contractManifestBytes);
    validateRunnerReport(referenceReport, contractManifestSha256, 'ogvcs.protocol/reference-js@1', contractManifest.counts.scenarios);
    validateRunnerReport(independentReport, contractManifestSha256, 'ogvcs.protocol/independent-js@1', contractManifest.counts.scenarios);
    if (referenceReport.reportDigest !== independentReport.reportDigest || canonicalJson(referenceReport.results) !== canonicalJson(independentReport.results)) {
      throw new Error('packed reference and independent adapter decisions differ');
    }

    const offlineSource = await buildOfflineSource(destination, environment);
    const bindingManifestBytes = await readFile(join(destination, 'offline-source/foundation/protocol-baseline/bindings/manifest.json'));
    const bindingManifest = JSON.parse(bindingManifestBytes);
    if (bindingManifest.contractManifestSha256 !== contractManifestSha256 || bindingManifest.license !== 'MIT') throw new Error('offline binding sources do not bind the packed contract');
    const evidence = {
      schemaVersion: 'ogvcs.protocol/packed-evidence/v1',
      adapterIsolation: 'node-permission-isolated-package-staged-authority-v1',
      contractVersion: contractManifest.contractVersion,
      contractManifestSha256,
      registrySetSha256: contractManifest.registrySetSha256,
      schemaSetSha256: contractManifest.schemaSetSha256,
      vectorSetSha256: contractManifest.vectorSetSha256,
      modelSha256: contractManifest.modelSha256,
      generatorSha256: contractManifest.generatorSha256,
      bindingManifestSha256: sha256(bindingManifestBytes),
      bindingSetSha256: bindingManifest.bindingSetSha256,
      sourceSetSha256: offlineSource.sourceSetSha256,
      license: 'MIT',
      licenseSha256: sha256(await readFile(ROOT_LICENSE)),
      platform: hostPlatform(),
      scenarios: contractManifest.counts.scenarios,
      packages: packageRecords.map(({ path: _path, ...record }) => record).sort((left, right) => left.name.localeCompare(right.name)),
      reports: [
        { adapterId: referenceReport.adapterId, filename: basename(referencePath), reportDigest: referenceReport.reportDigest, sha256: sha256(referenceBytes) },
        { adapterId: independentReport.adapterId, filename: basename(independentPath), reportDigest: independentReport.reportDigest, sha256: sha256(independentBytes) },
      ],
      result: 'pass',
    };
    await writeCanonical(join(destination, 'packed-evidence.json'), evidence);
    return evidence;
  } finally {
    await rm(scratch, { recursive: true, force: true, maxRetries: 8, retryDelay: 50 });
    if (adapterScratch !== undefined) await rm(adapterScratch, { recursive: true, force: true, maxRetries: 8, retryDelay: 50 });
  }
}

const isMain = process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url;
if (isMain) {
  const output = parseArguments(process.argv.slice(2));
  const evidence = await runPackedProtocolConformance(output);
  process.stdout.write(`${JSON.stringify({ output, platform: evidence.platform, packages: evidence.packages.length, scenarios: evidence.scenarios, result: evidence.result })}\n`);
}
