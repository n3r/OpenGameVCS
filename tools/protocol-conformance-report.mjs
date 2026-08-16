#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { cp, lstat, mkdir, mkdtemp, open, readFile, readdir, rename, rm, unlink } from 'node:fs/promises';
import { platform, tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

import {
  canonicalBytes,
  loadProtocolContract,
  runExternalProtocolConformance,
  runReferenceProtocolConformance,
} from '../foundation/protocol-baseline/js/src/index.mjs';

const REPOSITORY = resolve(import.meta.dirname, '..');
const ROOT_LICENSE = join(REPOSITORY, 'LICENSE');
const CONTRACT = join(REPOSITORY, 'spec/protocols/v1');
const BINDING_MANIFEST = join(REPOSITORY, 'foundation/protocol-baseline/bindings/manifest.json');
const INDEPENDENT_SOURCE = join(REPOSITORY, 'foundation/protocol-baseline/adapters/js-independent');
const AUTHORIZATION_RUNTIME_SOURCE = join(REPOSITORY, 'core/authz-contract/js');
const EXPECTED_REFERENCE = 'ogvcs.protocol/reference-js@1';
const EXPECTED_INDEPENDENT = 'ogvcs.protocol/independent-js@1';

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function hostPlatform() {
  return { linux: 'linux', darwin: 'macos', win32: 'windows' }[platform()] ?? platform();
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

function parseArguments(args) {
  if (args.length !== 2 || args[0] !== '--output' || !args[1] || args[1].includes('\0')) {
    throw new Error('usage: node tools/protocol-conformance-report.mjs --output <directory>');
  }
  return resolve(args[1]);
}

async function writeAtomic(path, value) {
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.tmp-${process.pid}-${Date.now()}`;
  let handle;
  try {
    handle = await open(temporary, 'wx', 0o600);
    await handle.writeFile(Buffer.concat([canonicalBytes(value), Buffer.from('\n')]));
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

async function copyPackagePayload(source, destination) {
  const manifest = JSON.parse(await readFile(join(source, 'package.json')));
  if (!Array.isArray(manifest.files) || manifest.files.length === 0 || manifest.files.length > 256) throw new Error(`package has no finite file inventory: ${manifest.name}`);
  await mkdir(destination, { recursive: true });
  await cp(join(source, 'package.json'), join(destination, 'package.json'), { errorOnExist: true, force: false });
  for (const entry of manifest.files) {
    if (typeof entry !== 'string' || entry.includes('\\') || entry.startsWith('/') || entry.split('/').some((part) => part === '' || part === '.' || part === '..')) {
      throw new Error(`package has an unsafe file entry: ${manifest.name}`);
    }
    await cp(join(source, entry), join(destination, entry), { recursive: true, errorOnExist: true, force: false });
  }
}

async function verifyIsolatedClosure(root) {
  let files = 0;
  const walk = async (directory) => {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      const metadata = await lstat(path);
      if (metadata.isSymbolicLink()) throw new Error('isolated adapter closure contains a symbolic link');
      if (metadata.isDirectory()) await walk(path);
      else if (metadata.isFile()) {
        files += 1;
        if (files > 4096) throw new Error('isolated adapter closure contains too many files');
      } else throw new Error('isolated adapter closure contains a non-regular entry');
    }
  };
  await walk(root);
  if (files === 0) throw new Error('isolated adapter closure is empty');
}

async function stageIndependentAdapter() {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-protocol-source-adapter-'));
  const scope = join(root, 'node_modules/@opengamevcs');
  try {
    await copyPackagePayload(INDEPENDENT_SOURCE, join(scope, 'protocol-baseline-independent-adapter'));
    await copyPackagePayload(AUTHORIZATION_RUNTIME_SOURCE, join(scope, 'authorization-contract'));
    await verifyIsolatedClosure(root);
    return {
      root,
      command: join(scope, 'protocol-baseline-independent-adapter/bin/ogvcs-protocol-independent-adapter.mjs'),
    };
  } catch (error) {
    await rm(root, { recursive: true, force: true, maxRetries: 8, retryDelay: 50 });
    throw error;
  }
}

function validateReport(report, contract, adapterId) {
  const count = contract.manifest.counts.scenarios;
  const keys = report && typeof report === 'object' ? Object.keys(report).sort() : [];
  const expectedKeys = ['adapterId', 'contractManifestSha256', 'failed', 'passed', 'reportDigest', 'results', 'schemaVersion'].sort();
  if (keys.length !== expectedKeys.length
      || keys.some((key, index) => key !== expectedKeys[index])
      || report?.schemaVersion !== 'ogvcs.protocol/runner-report/v1'
      || report.adapterId !== adapterId
      || report.contractManifestSha256 !== contract.manifestSha256
      || report.passed !== count
      || report.failed !== 0
      || !Array.isArray(report.results)
      || report.results.length !== count
      || !/^[0-9a-f]{64}$/u.test(report.reportDigest)
      || sha256(canonicalBytes(report.results)) !== report.reportDigest) {
    throw new Error(`protocol conformance report is invalid: ${adapterId}`);
  }
  validateResultRows(report.results, adapterId);
}

export async function buildProtocolConformanceEvidence(output) {
  const destination = resolve(output);
  const adapter = await stageIndependentAdapter();
  try {
    const contract = await loadProtocolContract({ root: CONTRACT, cache: false });
    const bindingBytes = await readFile(BINDING_MANIFEST);
    const bindings = JSON.parse(bindingBytes);
    if (bindings.schemaVersion !== 'ogvcs.protocol/binding-manifest/v1'
        || bindings.contractManifestSha256 !== contract.manifestSha256
        || bindings.contractVersion !== contract.manifest.contractVersion
        || bindings.license !== 'MIT') {
      throw new Error('binding manifest does not bind the loaded protocol contract');
    }

    const reference = await runReferenceProtocolConformance(contract, { adapterId: EXPECTED_REFERENCE });
    const independent = await runExternalProtocolConformance(contract, [
      process.execPath,
      adapter.command,
      '--contract',
      CONTRACT,
    ], { expectedAdapterId: EXPECTED_INDEPENDENT, nodeAdapterReadRoots: [adapter.root] });
    validateReport(reference, contract, EXPECTED_REFERENCE);
    validateReport(independent, contract, EXPECTED_INDEPENDENT);
    if (reference.reportDigest !== independent.reportDigest
        || Buffer.compare(canonicalBytes(reference.results), canonicalBytes(independent.results)) !== 0) {
      throw new Error('reference and independent protocol decisions differ');
    }

    const referencePath = join(destination, 'reference-report.json');
    const independentPath = join(destination, 'independent-report.json');
    await writeAtomic(referencePath, reference);
    await writeAtomic(independentPath, independent);
    const referenceBytes = await readFile(referencePath);
    const independentBytes = await readFile(independentPath);
    const evidence = {
      schemaVersion: 'ogvcs.protocol/conformance-evidence/v1',
      adapterIsolation: 'node-permission-isolated-package-staged-authority-v1',
      contractVersion: contract.manifest.contractVersion,
      contractManifestSha256: contract.manifestSha256,
      registrySetSha256: contract.manifest.registrySetSha256,
      schemaSetSha256: contract.manifest.schemaSetSha256,
      vectorSetSha256: contract.manifest.vectorSetSha256,
      modelSha256: contract.manifest.modelSha256,
      generatorSha256: contract.manifest.generatorSha256,
      bindingManifestSha256: sha256(bindingBytes),
      bindingSetSha256: bindings.bindingSetSha256,
      license: 'MIT',
      licenseSha256: sha256(await readFile(ROOT_LICENSE)),
      platform: hostPlatform(),
      scenarios: contract.manifest.counts.scenarios,
      reports: [
        { adapterId: reference.adapterId, filename: basename(referencePath), reportDigest: reference.reportDigest, sha256: sha256(referenceBytes) },
        { adapterId: independent.adapterId, filename: basename(independentPath), reportDigest: independent.reportDigest, sha256: sha256(independentBytes) },
      ],
      result: 'pass',
    };
    await writeAtomic(join(destination, 'conformance-evidence.json'), evidence);
    return evidence;
  } finally {
    await rm(adapter.root, { recursive: true, force: true, maxRetries: 8, retryDelay: 50 });
  }
}

const isMain = process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url;
if (isMain) {
  const output = parseArguments(process.argv.slice(2));
  const evidence = await buildProtocolConformanceEvidence(output);
  process.stdout.write(`${JSON.stringify({ output, platform: evidence.platform, scenarios: evidence.scenarios, result: evidence.result })}\n`);
}
