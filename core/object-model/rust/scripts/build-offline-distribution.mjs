#!/usr/bin/env node

import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { createReadStream } from 'node:fs';
import {
  copyFile,
  cp,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  stat,
  writeFile
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const CRATE_ROOT = resolve(import.meta.dirname, '..');
const REPOSITORY_ROOT = resolve(CRATE_ROOT, '../../..');
const FORMAT_ROOT = join(REPOSITORY_ROOT, 'spec', 'repository-format', 'v1');
const NPM_CLI = process.env.npm_execpath ?? (process.platform === 'win32'
  ? join(dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js')
  : undefined);
const MANIFEST_NAME = 'MANIFEST.json';
const INCOMPLETE_NAME = '.INCOMPLETE';
const SCHEMA = 'ogvcs.rust-offline-distribution/v1';
const RESULT_SCHEMA = 'ogvcs.rust-offline-distribution-result/v1';
const SOURCE_CONFIG = `[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"

[net]
offline = true
`;
const SMOKE_OUTPUT = 'ogvcs-offline-public-api-smoke-ok';
const FORMAT_SMOKE_OUTPUT = 'ogvcs-offline-format-smoke-ok';

function fail(message) {
  throw new Error(message);
}

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) fail('manifest contains a non-integer number');
    return String(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (typeof value === 'object') {
    const keys = Object.keys(value).sort(compareText);
    return `{${keys.map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  fail('manifest contains an unsupported value');
}

function tomlString(text) {
  if (!/^"(?:[^"\\]|\\.)*"$/.test(text)) fail('unsupported TOML string');
  return JSON.parse(text);
}

function packageMetadata(text) {
  let inPackage = false;
  const values = new Map();
  for (const sourceLine of text.split(/\r?\n/u)) {
    const line = sourceLine.trim();
    if (line === '[package]') {
      inPackage = true;
      continue;
    }
    if (line.startsWith('[')) {
      if (inPackage) break;
      continue;
    }
    if (!inPackage || line === '' || line.startsWith('#')) continue;
    const match = /^([A-Za-z0-9_-]+)\s*=\s*("(?:[^"\\]|\\.)*")\s*$/u.exec(line);
    if (match) values.set(match[1], tomlString(match[2]));
  }
  const name = values.get('name');
  const version = values.get('version');
  if (!name || !version) fail('Cargo.toml has no literal package name and version');
  return {
    name,
    version,
    licenseExpression: values.get('license') ?? null,
    licenseFile: values.get('license-file') ?? null
  };
}

function lockDependencies(text) {
  const dependencies = [];
  const blocks = text.split(/^\[\[package\]\]\s*$/mu).slice(1);
  for (const block of blocks) {
    const literal = key => {
      const match = new RegExp(`^${key}\\s*=\\s*("(?:[^"\\\\]|\\\\.)*")\\s*$`, 'mu').exec(block);
      return match ? tomlString(match[1]) : null;
    };
    const name = literal('name');
    const version = literal('version');
    const source = literal('source');
    const checksum = literal('checksum');
    if (!name || !version) fail('Cargo.lock contains an incomplete package');
    if (source === null && checksum === null) continue;
    if (!source?.startsWith('registry+https://github.com/rust-lang/crates.io-index')) {
      fail(`unsupported non-crates.io dependency ${name}`);
    }
    if (!/^[0-9a-f]{64}$/u.test(checksum ?? '')) fail(`invalid checksum for ${name}`);
    dependencies.push({ name, version, source, checksum });
  }
  dependencies.sort((left, right) =>
    compareText(left.name, right.name) || compareText(left.version, right.version));
  const identities = new Set(dependencies.map(item => `${item.name}\0${item.version}`));
  if (identities.size !== dependencies.length) fail('Cargo.lock has duplicate dependency identities');
  return dependencies;
}

function safeRelativePath(path) {
  if (typeof path !== 'string' || path === '' || path.includes('\\') || path.includes('\0')) return false;
  const parts = path.split('/');
  return !path.startsWith('/') && parts.every(part => part !== '' && part !== '.' && part !== '..');
}

function localPath(root, relative) {
  if (!safeRelativePath(relative)) fail('unsafe relative path');
  return join(root, ...relative.split('/'));
}

async function hashFile(path) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest('hex');
}

async function fileRecord(root, relative) {
  const path = localPath(root, relative);
  const metadata = await stat(path);
  if (!metadata.isFile()) fail('bundle contains a non-file leaf');
  return { path: relative, bytes: metadata.size, sha256: await hashFile(path) };
}

async function listFiles(root, prefix = '') {
  const directory = prefix === '' ? root : localPath(root, prefix);
  const entries = await readdir(directory, { withFileTypes: true });
  entries.sort((left, right) => compareText(left.name, right.name));
  const files = [];
  for (const entry of entries) {
    const relative = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
    if (!safeRelativePath(relative)) fail('bundle contains an unsafe path');
    if (entry.isSymbolicLink()) fail('bundle contains a symbolic link');
    if (entry.isDirectory()) files.push(...await listFiles(root, relative));
    else if (entry.isFile()) files.push(relative);
    else fail('bundle contains an unsupported filesystem entry');
  }
  return files;
}

async function run(command, args, { cwd, env = process.env } = {}) {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(command, args, {
      cwd,
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true
    });
    const stdout = [];
    const stderr = [];
    child.stdout.on('data', chunk => stdout.push(chunk));
    child.stderr.on('data', chunk => stderr.push(chunk));
    child.once('error', rejectPromise);
    child.once('close', (code, signal) => resolvePromise({
      code,
      signal,
      stdout: Buffer.concat(stdout).toString('utf8'),
      stderr: Buffer.concat(stderr).toString('utf8')
    }));
  });
}

async function requireSuccess(command, args, options) {
  const result = await run(command, args, options);
  if (result.code !== 0) {
    const detail = (result.stderr || result.stdout).trim();
    fail(`${basename(command)} failed${detail === '' ? '' : `: ${detail}`}`);
  }
  return result;
}

function requireNpmSuccess(args, options) {
  if (NPM_CLI) return requireSuccess(process.execPath, [NPM_CLI, ...args], options);
  return requireSuccess('npm', args, options);
}

async function validateVendor(bundleRoot, lockText) {
  const expected = lockDependencies(lockText);
  const vendorRoot = join(bundleRoot, 'vendor');
  const directoryEntries = await readdir(vendorRoot, { withFileTypes: true });
  const actualDirectories = directoryEntries
    .filter(entry => entry.isDirectory() && !entry.isSymbolicLink())
    .map(entry => entry.name)
    .sort(compareText);
  if (directoryEntries.some(entry => !entry.isDirectory() || entry.isSymbolicLink())) {
    fail('vendor root contains a non-directory entry');
  }
  const expectedDirectories = expected.map(item => `${item.name}-${item.version}`).sort(compareText);
  if (canonicalJson(actualDirectories) !== canonicalJson(expectedDirectories)) {
    fail('vendored dependency set does not match Cargo.lock');
  }

  const result = [];
  for (const dependency of expected) {
    const directoryName = `${dependency.name}-${dependency.version}`;
    const dependencyRoot = join(vendorRoot, directoryName);
    const checksumPath = join(dependencyRoot, '.cargo-checksum.json');
    const checksumText = await readFile(checksumPath, 'utf8');
    const checksumManifest = JSON.parse(checksumText);
    if (checksumManifest.package !== dependency.checksum
        || checksumManifest.files === null
        || typeof checksumManifest.files !== 'object'
        || Array.isArray(checksumManifest.files)) {
      fail(`invalid cargo checksum manifest for ${dependency.name}`);
    }
    const checksumFiles = Object.keys(checksumManifest.files).sort(compareText);
    for (const relative of checksumFiles) {
      if (!safeRelativePath(relative)
          || !/^[0-9a-f]{64}$/u.test(checksumManifest.files[relative])) {
        fail(`invalid vendored file record for ${dependency.name}`);
      }
      if (await hashFile(localPath(dependencyRoot, relative)) !== checksumManifest.files[relative]) {
        fail(`vendored source checksum mismatch for ${dependency.name}`);
      }
    }
    const actualFiles = (await listFiles(dependencyRoot))
      .filter(relative => relative !== '.cargo-checksum.json')
      .sort(compareText);
    if (canonicalJson(actualFiles) !== canonicalJson(checksumFiles)) {
      fail(`vendored source inventory mismatch for ${dependency.name}`);
    }

    const metadata = packageMetadata(await readFile(join(dependencyRoot, 'Cargo.toml'), 'utf8'));
    if (metadata.name !== dependency.name || metadata.version !== dependency.version) {
      fail(`vendored Cargo.toml identity mismatch for ${dependency.name}`);
    }
    if (metadata.licenseExpression === null && metadata.licenseFile === null) {
      fail(`vendored dependency has no declared license metadata: ${dependency.name}`);
    }
    const licensePaths = actualFiles.filter(relative =>
      /^(?:license|copying|notice)(?:$|[._-])/iu.test(basename(relative)));
    if (metadata.licenseFile !== null && !licensePaths.includes(metadata.licenseFile)) {
      fail(`declared license file is absent for ${dependency.name}`);
    }
    if (licensePaths.length === 0) fail(`vendored dependency has no license artifact: ${dependency.name}`);
    const licenseFiles = [];
    for (const relative of licensePaths) {
      const record = await fileRecord(dependencyRoot, relative);
      licenseFiles.push(record);
    }
    const treeHash = createHash('sha256');
    for (const relative of checksumFiles) {
      treeHash.update(`${checksumManifest.files[relative]}  ${relative}\n`, 'utf8');
    }
    result.push({
      name: dependency.name,
      version: dependency.version,
      source: dependency.source,
      packageChecksum: dependency.checksum,
      cargoChecksumManifestSha256: await hashFile(checksumPath),
      vendorTreeSha256: treeHash.digest('hex'),
      licenseExpression: metadata.licenseExpression,
      licenseFile: metadata.licenseFile,
      licenseFiles
    });
  }
  return result;
}

function consumerCargoToml(packageName, packageVersion, packageDirectory) {
  return `[package]
name = "ogvcs-offline-consumer-smoke"
version = "0.0.0"
edition = "2021"
publish = false

[dependencies]
${packageName} = { package = "${packageName}", version = "=${packageVersion}", path = "../package/${packageDirectory}" }
`;
}

const CONSUMER_MAIN = `use std::str::FromStr;

use ogvcs_object_model::{sha256, ObjectKind, ObjectRef};

fn main() {
    let object_ref = ObjectRef {
        kind: ObjectKind::Chunk,
        digest: sha256(b"offline-public-api-smoke"),
    };
    let encoded = object_ref.to_string();
    assert_eq!(ObjectRef::from_str(&encoded).expect("public ObjectRef parse"), object_ref);
    println!("ogvcs-offline-public-api-smoke-ok");
}
`;

function offlineReadme(packageName, packageVersion, packageDirectory) {
  return `# ${packageName} offline distribution ${packageVersion}

This directory is a content-addressed offline distribution. \`MANIFEST.json\`
inventories every file except itself, records the exact Cargo.lock dependency
versions and checksums, and hashes every preserved upstream license artifact.

The verified Cargo archive is \`archive/${packageDirectory}.crate\`. Its unpacked,
verified source is \`package/${packageDirectory}\`. Cargo source replacement is
fixed in \`.cargo/config.toml\`, and all third-party source is under \`vendor/\`.
The versioned data-only format package under \`conformance/\` contains the
normative prose, CDDL, registries, and complete vector corpus used by both
language implementations.

From this directory, with Rust already installed, run the public API proof with:

    cargo run --manifest-path smoke-consumer/Cargo.toml --locked --offline

No registry or network access is required or permitted by the bundled config.
The packed format artifact can likewise be installed with \`npm install
--offline conformance/opengamevcs-repository-format-v1-<version>.tgz\`.
`;
}

async function createConsumer(bundleRoot, metadata) {
  const packageDirectory = `${metadata.name}-${metadata.version}`;
  const consumer = join(bundleRoot, 'smoke-consumer');
  await mkdir(join(consumer, 'src'), { recursive: true });
  await writeFile(
    join(consumer, 'Cargo.toml'),
    consumerCargoToml(metadata.name, metadata.version, packageDirectory),
    'utf8'
  );
  await writeFile(join(consumer, 'src', 'main.rs'), CONSUMER_MAIN, 'utf8');
}

async function runConsumerSmoke(bundleRoot, cargo, scratchRoot) {
  const cargoHome = join(scratchRoot, 'empty-cargo-home');
  const target = join(scratchRoot, 'consumer-target');
  await mkdir(cargoHome, { recursive: false });
  const environment = {
    ...process.env,
    CARGO_HOME: cargoHome,
    CARGO_NET_OFFLINE: 'true',
    CARGO_TARGET_DIR: target
  };
  const manifest = join(bundleRoot, 'smoke-consumer', 'Cargo.toml');
  if (!(await fileExists(join(bundleRoot, 'smoke-consumer', 'Cargo.lock')))) {
    await requireSuccess(cargo, [
      'generate-lockfile', '--manifest-path', manifest, '--offline'
    ], { cwd: bundleRoot, env: environment });
  }
  const result = await requireSuccess(cargo, [
    'run', '--manifest-path', manifest, '--locked', '--offline', '--quiet'
  ], { cwd: bundleRoot, env: environment });
  if (result.stdout.trim() !== SMOKE_OUTPUT) fail('offline public API smoke returned unexpected output');
}

async function formatMetadata() {
  const value = JSON.parse(await readFile(join(FORMAT_ROOT, 'package.json'), 'utf8'));
  if (value?.name !== '@opengamevcs/repository-format-v1' ||
      value.license !== 'MIT' || value.files?.includes('LICENSE') !== true ||
      typeof value.version !== 'string' || !/^0\.[0-9]+\.[0-9]+$/u.test(value.version)) {
    fail('format package identity is invalid');
  }
  return Object.freeze({
    name: value.name,
    version: value.version,
    archiveName: `opengamevcs-repository-format-v1-${value.version}.tgz`
  });
}

async function runFormatSmoke(bundleRoot, scratchRoot, metadata) {
  const consumer = join(scratchRoot, 'format-consumer');
  const cache = join(scratchRoot, 'npm-cache');
  await mkdir(consumer, { recursive: false });
  await writeFile(join(consumer, 'package.json'), '{"private":true,"type":"module"}\n', 'utf8');
  const environment = {
    ...process.env,
    npm_config_audit: 'false',
    npm_config_cache: cache,
    npm_config_fund: 'false',
    npm_config_offline: 'true'
  };
  const archive = join(bundleRoot, 'conformance', metadata.archiveName);
  await requireNpmSuccess([
    'install', '--offline', '--ignore-scripts', '--no-audit', '--no-fund',
    '--package-lock=false', archive
  ], { cwd: consumer, env: environment });
  const installedFormat = join(consumer, 'node_modules', '@opengamevcs', 'repository-format-v1');
  const installedMetadata = JSON.parse(await readFile(join(installedFormat, 'package.json'), 'utf8'));
  if (installedMetadata.license !== 'MIT' ||
      await readFile(join(installedFormat, 'LICENSE'), 'utf8') !==
        await readFile(join(FORMAT_ROOT, 'LICENSE'), 'utf8')) {
    fail('offline format package license mismatch');
  }
  await writeFile(join(consumer, 'smoke.mjs'), `
import { readFile } from 'node:fs/promises';
import { formatVersion, registriesUrl, vectorsUrl } from '@opengamevcs/repository-format-v1';
if (formatVersion !== 1) throw new Error('format version mismatch');
const manifest = JSON.parse(await readFile(new URL('manifest.json', vectorsUrl), 'utf8'));
const kinds = JSON.parse(await readFile(new URL('object-kinds.json', registriesUrl), 'utf8'));
if (manifest.manifestVersion !== 'ogvcs.repository-format/vector-manifest/v1' ||
    kinds.registry !== 'ogvcs.repository-format.object-kinds') throw new Error('format data mismatch');
process.stdout.write('${FORMAT_SMOKE_OUTPUT}\\n');
`, 'utf8');
  const result = await requireSuccess(process.execPath, [join(consumer, 'smoke.mjs')], {
    cwd: consumer,
    env: environment
  });
  if (result.stdout.trim() !== FORMAT_SMOKE_OUTPUT) fail('offline format smoke returned unexpected output');
}

async function fileExists(path) {
  try {
    await lstat(path);
    return true;
  } catch (error) {
    if (error?.code === 'ENOENT') return false;
    throw error;
  }
}

async function packagedVcsInfo(bundleRoot, packageDirectory) {
  const path = join(bundleRoot, 'package', packageDirectory, '.cargo_vcs_info.json');
  if (!(await fileExists(path))) return { sourceRevision: null, sourceTreeDirty: null };
  const value = JSON.parse(await readFile(path, 'utf8'));
  const sourceRevision = value?.git?.sha1;
  const sourceTreeDirty = value?.git?.dirty;
  if (!/^[0-9a-f]{40}$/u.test(sourceRevision ?? '') || typeof sourceTreeDirty !== 'boolean') {
    fail('packaged crate has invalid VCS metadata');
  }
  return { sourceRevision, sourceTreeDirty };
}

async function manifestFor(bundleRoot, metadata, dependencies, allowDirty, format) {
  const excluded = new Set([MANIFEST_NAME, INCOMPLETE_NAME]);
  const relativeFiles = (await listFiles(bundleRoot))
    .filter(path => !excluded.has(path))
    .sort(compareText);
  const files = [];
  for (const relative of relativeFiles) files.push(await fileRecord(bundleRoot, relative));
  const byPath = new Map(files.map(file => [file.path, file]));
  const packageDirectory = `${metadata.name}-${metadata.version}`;
  const archivePath = `archive/${packageDirectory}.crate`;
  const lockPath = 'Cargo.lock';
  const licensePath = 'LICENSE';
  const configPath = '.cargo/config.toml';
  const formatArchivePath = `conformance/${format.archiveName}`;
  if (!byPath.has(archivePath) || !byPath.has(lockPath) ||
      !byPath.has(licensePath) || !byPath.has(configPath)) {
    fail('offline distribution is missing a required artifact');
  }
  if (!byPath.has(formatArchivePath)) fail('offline distribution is missing the packed format artifact');
  const vcs = await packagedVcsInfo(bundleRoot, packageDirectory);
  if (!allowDirty && vcs.sourceTreeDirty === true) fail('clean package unexpectedly reports dirty VCS state');
  return {
    schema: SCHEMA,
    package: {
      name: metadata.name,
      version: metadata.version,
      licenseExpression: metadata.licenseExpression,
      licenseArtifact: byPath.get(licensePath),
      crateArchive: byPath.get(archivePath),
      verifiedSourceDirectory: `package/${packageDirectory}`,
      sourceRevision: vcs.sourceRevision,
      sourceTreeDirty: vcs.sourceTreeDirty
    },
    cargoLock: byPath.get(lockPath),
    conformance: {
      packageName: format.name,
      version: format.version,
      archive: byPath.get(formatArchivePath)
    },
    sourceReplacementConfig: byPath.get(configPath),
    dependencies,
    verification: {
      packageCommand: allowDirty
        ? 'cargo package --locked --offline --allow-dirty'
        : 'cargo package --locked --offline',
      dirtySourceAllowed: allowDirty,
      consumerCommand: 'cargo run --manifest-path smoke-consumer/Cargo.toml --locked --offline',
      formatConsumerCommand: `npm install --offline conformance/${format.archiveName}`,
      emptyCargoHome: true,
      offlineFormatVerified: true,
      publicApiSmokeOutput: SMOKE_OUTPUT
    },
    canonicalization: {
      format: 'sorted-key UTF-8 JSON integer subset',
      selfHashExcludedPath: MANIFEST_NAME
    },
    files
  };
}

async function verifyBundle(
  bundleRoot,
  cargo,
  { runSmoke = true, allowIncomplete = false, allowStagingName = false } = {}
) {
  const rootMetadata = await lstat(bundleRoot);
  if (rootMetadata.isSymbolicLink() || !rootMetadata.isDirectory()) fail('bundle root is not a safe directory');
  const manifestText = await readFile(join(bundleRoot, MANIFEST_NAME), 'utf8');
  const manifest = JSON.parse(manifestText);
  if (manifestText !== `${canonicalJson(manifest)}\n`) fail('offline manifest is not canonical');
  if (manifest.schema !== SCHEMA) fail('offline manifest schema mismatch');
  const expectedName = `ogvcs-object-model-offline-${manifest.package?.version ?? ''}`;
  if (!allowStagingName && basename(bundleRoot) !== expectedName) {
    fail('offline bundle directory is not versioned');
  }

  const listedFiles = manifest.files;
  if (!Array.isArray(listedFiles)) fail('offline manifest has no file inventory');
  const expectedPaths = listedFiles.map(record => record.path);
  if (canonicalJson(expectedPaths) !== canonicalJson([...expectedPaths].sort(compareText))
      || new Set(expectedPaths).size !== expectedPaths.length) {
    fail('offline manifest file inventory is not sorted and unique');
  }
  const allActualPaths = await listFiles(bundleRoot);
  if (!allowIncomplete && allActualPaths.includes(INCOMPLETE_NAME)) fail('offline bundle is incomplete');
  const actualPaths = allActualPaths
    .filter(path => path !== MANIFEST_NAME && path !== INCOMPLETE_NAME)
    .sort(compareText);
  if (canonicalJson(actualPaths) !== canonicalJson(expectedPaths)) fail('offline manifest file inventory mismatch');
  for (const expected of listedFiles) {
    if (!safeRelativePath(expected.path)
        || !Number.isSafeInteger(expected.bytes)
        || expected.bytes < 0
        || !/^[0-9a-f]{64}$/u.test(expected.sha256)) {
      fail('offline manifest contains an invalid file record');
    }
    const actual = await fileRecord(bundleRoot, expected.path);
    if (canonicalJson(actual) !== canonicalJson(expected)) fail(`offline file hash mismatch: ${expected.path}`);
  }
  if (await readFile(join(bundleRoot, '.cargo', 'config.toml'), 'utf8') !== SOURCE_CONFIG) {
    fail('offline source replacement config mismatch');
  }
  const byPath = new Map(listedFiles.map(file => [file.path, file]));
  const packageDirectory = `${manifest.package.name}-${manifest.package.version}`;
  const archivePath = `archive/${packageDirectory}.crate`;
  if (canonicalJson(manifest.package.crateArchive) !== canonicalJson(byPath.get(archivePath))
      || canonicalJson(manifest.package.licenseArtifact) !== canonicalJson(byPath.get('LICENSE'))
      || canonicalJson(manifest.cargoLock) !== canonicalJson(byPath.get('Cargo.lock'))
      || canonicalJson(manifest.sourceReplacementConfig)
        !== canonicalJson(byPath.get('.cargo/config.toml'))) {
    fail('offline manifest artifact linkage mismatch');
  }
  const expectedFormat = await formatMetadata();
  const formatArchivePath = `conformance/${expectedFormat.archiveName}`;
  if (manifest.conformance?.packageName !== expectedFormat.name ||
      manifest.conformance?.version !== expectedFormat.version ||
      canonicalJson(manifest.conformance?.archive) !== canonicalJson(byPath.get(formatArchivePath)) ||
      manifest.verification?.offlineFormatVerified !== true) {
    fail('offline format artifact linkage mismatch');
  }
  const lockText = await readFile(join(bundleRoot, 'Cargo.lock'), 'utf8');
  const dependencies = await validateVendor(bundleRoot, lockText);
  if (canonicalJson(dependencies) !== canonicalJson(manifest.dependencies)) {
    fail('offline dependency manifest mismatch');
  }
  const packagedMetadata = packageMetadata(await readFile(
    join(bundleRoot, 'package', packageDirectory, 'Cargo.toml.orig'), 'utf8'));
  if (packagedMetadata.name !== manifest.package.name
      || packagedMetadata.version !== manifest.package.version
      || packagedMetadata.licenseExpression !== manifest.package.licenseExpression) {
    fail('packaged crate metadata mismatch');
  }
  const distributionLicense = await readFile(join(bundleRoot, 'LICENSE'), 'utf8');
  const packagedLicense = await readFile(join(
    bundleRoot, 'package', packageDirectory, 'LICENSE'), 'utf8');
  if (distributionLicense !== packagedLicense || !distributionLicense.startsWith('MIT License\n')) {
    fail('packaged crate license mismatch');
  }
  const vcs = await packagedVcsInfo(bundleRoot, packageDirectory);
  if (manifest.package.sourceRevision !== vcs.sourceRevision
      || manifest.package.sourceTreeDirty !== vcs.sourceTreeDirty
      || (vcs.sourceTreeDirty === true && manifest.verification.dirtySourceAllowed !== true)) {
    fail('packaged crate VCS state mismatch');
  }
  if (runSmoke) {
    const scratch = await mkdtemp(join(tmpdir(), 'ogvcs-offline-verify-'));
    try {
      await runConsumerSmoke(bundleRoot, cargo, scratch);
      await runFormatSmoke(bundleRoot, scratch, expectedFormat);
    } finally {
      await rm(scratch, { recursive: true, force: true, maxRetries: 8, retryDelay: 100 });
    }
  }
  return manifest;
}

async function safeOutput(path, version) {
  const output = resolve(path);
  const expectedName = `ogvcs-object-model-offline-${version}`;
  if (basename(output) !== expectedName) fail(`output directory must be named ${expectedName}`);
  const parent = dirname(output);
  const metadata = await lstat(parent);
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) fail('output parent is not a safe directory');
  if (await fileExists(output)) fail('output directory already exists');
  return { output, parent };
}

async function buildOfflineDistribution(outputPath, cargo, { allowDirty = false } = {}) {
  const crateToml = await readFile(join(CRATE_ROOT, 'Cargo.toml'), 'utf8');
  const metadata = packageMetadata(crateToml);
  const format = await formatMetadata();
  if (format.version !== metadata.version) fail('crate and packed format versions differ');
  if (metadata.name !== 'ogvcs-object-model' || metadata.licenseExpression !== 'MIT') {
    fail('crate identity or declared license changed; review is required');
  }
  const { output, parent } = await safeOutput(outputPath, metadata.version);
  const stage = join(parent, `.${basename(output)}.staging-${randomBytes(12).toString('hex')}`);
  await mkdir(stage, { recursive: false });
  let published = false;
  try {
    await writeFile(join(stage, INCOMPLETE_NAME), 'not a completed offline distribution\n', 'utf8');
    const work = join(stage, '.work');
    const packageTarget = join(work, 'package-target');
    await mkdir(work, { recursive: false });
    const packageEnvironment = { ...process.env, CARGO_TARGET_DIR: packageTarget };
    const packageArguments = [
      'package', '--manifest-path', join(CRATE_ROOT, 'Cargo.toml'), '--locked', '--offline'
    ];
    if (allowDirty) packageArguments.push('--allow-dirty');
    await requireSuccess(cargo, packageArguments, { cwd: CRATE_ROOT, env: packageEnvironment });

    const packageDirectory = `${metadata.name}-${metadata.version}`;
    const generatedRoot = join(packageTarget, 'package');
    const generatedArchive = join(generatedRoot, `${packageDirectory}.crate`);
    const generatedSource = join(generatedRoot, packageDirectory);
    await mkdir(join(stage, 'archive'), { recursive: false });
    await mkdir(join(stage, 'package'), { recursive: false });
    await copyFile(generatedArchive, join(stage, 'archive', `${packageDirectory}.crate`));
    await cp(generatedSource, join(stage, 'package', packageDirectory), {
      recursive: true,
      dereference: false,
      verbatimSymlinks: true
    });
    await copyFile(join(CRATE_ROOT, 'Cargo.lock'), join(stage, 'Cargo.lock'));
    await copyFile(join(CRATE_ROOT, 'LICENSE'), join(stage, 'LICENSE'));

    await mkdir(join(stage, 'conformance'), { recursive: false });
    const npmEnvironment = {
      ...process.env,
      npm_config_audit: 'false',
      npm_config_cache: join(work, 'npm-cache'),
      npm_config_fund: 'false',
      npm_config_offline: 'true'
    };
    const packedFormat = await requireNpmSuccess([
      'pack', FORMAT_ROOT, '--json', '--pack-destination', join(stage, 'conformance')
    ], { cwd: REPOSITORY_ROOT, env: npmEnvironment });
    let packResult;
    try { packResult = JSON.parse(packedFormat.stdout); } catch { fail('npm pack returned invalid JSON'); }
    if (!Array.isArray(packResult) || packResult.length !== 1 ||
        packResult[0]?.filename !== format.archiveName) fail('npm pack returned an unexpected format artifact');

    await requireSuccess(cargo, [
      'vendor', '--manifest-path', join(CRATE_ROOT, 'Cargo.toml'), '--locked', '--offline',
      '--versioned-dirs', join(stage, 'vendor')
    ], { cwd: CRATE_ROOT });
    await mkdir(join(stage, '.cargo'), { recursive: false });
    await writeFile(join(stage, '.cargo', 'config.toml'), SOURCE_CONFIG, 'utf8');
    await writeFile(join(stage, 'OFFLINE-README.md'), offlineReadme(
      metadata.name, metadata.version, packageDirectory
    ), 'utf8');
    await createConsumer(stage, metadata);

    const lockText = await readFile(join(stage, 'Cargo.lock'), 'utf8');
    const dependencies = await validateVendor(stage, lockText);
    const consumerScratch = join(work, 'consumer-proof');
    await mkdir(consumerScratch, { recursive: false });
    await runConsumerSmoke(stage, cargo, consumerScratch);
    await runFormatSmoke(stage, consumerScratch, format);
    await rm(work, { recursive: true, force: true, maxRetries: 8, retryDelay: 100 });

    const manifest = await manifestFor(stage, metadata, dependencies, allowDirty, format);
    await writeFile(join(stage, MANIFEST_NAME), `${canonicalJson(manifest)}\n`, 'utf8');
    await verifyBundle(stage, cargo, {
      runSmoke: true,
      allowIncomplete: true,
      allowStagingName: true
    });
    await rm(join(stage, INCOMPLETE_NAME), { force: false });
    await verifyBundle(stage, cargo, { runSmoke: false, allowStagingName: true });
    await rename(stage, output);
    published = true;
    const manifestSha256 = await hashFile(join(output, MANIFEST_NAME));
    return {
      schema: RESULT_SCHEMA,
      operation: 'build',
      bundle: basename(output),
      manifestSha256,
      dependencies: dependencies.length,
      offlineFormatVerified: true,
      offlineConsumerVerified: true
    };
  } finally {
    if (!published) {
      await rm(stage, { recursive: true, force: true, maxRetries: 8, retryDelay: 100 });
    }
  }
}

function usage() {
  return 'usage: node scripts/build-offline-distribution.mjs (--output PATH | --verify PATH) [--cargo PATH] [--allow-dirty]';
}

function parseArguments(argv) {
  let output = null;
  let verify = null;
  let allowDirty = false;
  let cargo = process.env.CARGO || (process.platform === 'win32' ? 'cargo.exe' : 'cargo');
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--output' && index + 1 < argv.length) output = argv[++index];
    else if (argument === '--verify' && index + 1 < argv.length) verify = argv[++index];
    else if (argument === '--cargo' && index + 1 < argv.length) cargo = argv[++index];
    else if (argument === '--allow-dirty') allowDirty = true;
    else fail(usage());
  }
  if ((output === null) === (verify === null)) fail(usage());
  if (verify !== null && allowDirty) fail('--allow-dirty is only valid with --output');
  return { output, verify, cargo, allowDirty };
}

export {
  buildOfflineDistribution,
  canonicalJson,
  verifyBundle
};

async function main() {
  const { output, verify, cargo, allowDirty } = parseArguments(process.argv.slice(2));
  let result;
  if (output !== null) {
    result = await buildOfflineDistribution(output, cargo, { allowDirty });
  } else {
    const bundle = resolve(verify);
    const manifest = await verifyBundle(bundle, cargo);
    result = {
      schema: RESULT_SCHEMA,
      operation: 'verify',
      bundle: basename(bundle),
      manifestSha256: await hashFile(join(bundle, MANIFEST_NAME)),
      dependencies: manifest.dependencies.length,
      offlineFormatVerified: true,
      offlineConsumerVerified: true
    };
  }
  process.stdout.write(`${canonicalJson(result)}\n`);
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  main().catch(error => {
    process.stderr.write(`offline distribution failed: ${error instanceof Error ? error.message : 'unknown error'}\n`);
    process.exitCode = 1;
  });
}
