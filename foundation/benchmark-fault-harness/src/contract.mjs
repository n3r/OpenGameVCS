import { constants as fsConstants } from 'node:fs';
import { open } from 'node:fs/promises';
import { resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { ProtocolSchemaValidator } from '@opengamevcs/protocol-baseline';

import { canonicalBytes, canonicalJson, codeUnitCompare, deepFreeze, parseJson, sha256 } from './canonical.mjs';
import { BenchmarkHarnessError, harnessFail } from './errors.mjs';
import { HARNESS_LIMITS, HarnessDeadline, boundedInteger, checkedAdd } from './limits.mjs';
import { snapshotOptions } from './input.mjs';

const PACKAGE = '@opengamevcs/benchmark-fault-contract-v1';
const SAFE_ASSET = /^(?:(?:schemas|registries|profiles|thresholds|vectors)\/[A-Za-z0-9._-]+\.json)$/u;
let defaultContract;

function rootUrl(options) {
  if (options.root !== undefined) {
    const value = options.root instanceof URL ? new URL(options.root.href) : pathToFileURL(`${resolve(options.root)}${sep}`);
    if (value.protocol !== 'file:' || value.search !== '' || value.hash !== '') harnessFail('HARNESS_INPUT_INVALID', 'benchmark contract root must be a local directory URL');
    return value.href.endsWith('/') ? value : new URL(`${value.href}/`);
  }
  try { return new URL('./', import.meta.resolve(`${PACKAGE}/manifest.json`)); }
  catch (error) { harnessFail('HARNESS_BUNDLE_INVALID', 'installed benchmark contract is unavailable', { cause: error }); }
}

function assetUrl(root, path) {
  if (typeof path !== 'string' || !SAFE_ASSET.test(path) || path.includes('..')) harnessFail('HARNESS_BUNDLE_INVALID', 'benchmark contract contains an unsafe artifact path');
  const value = new URL(path, root);
  if (!value.href.startsWith(root.href)) harnessFail('HARNESS_BUNDLE_INVALID', 'benchmark contract artifact escapes its root');
  return value;
}

async function readBounded(url, maximum, deadline) {
  let handle;
  try {
    deadline.checkpoint();
    handle = await deadline.race(open(fileURLToPath(url), fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0)), 'contract open');
    const before = await deadline.race(handle.stat(), 'contract stat');
    if (!before.isFile() || before.size < 1 || before.size > maximum) harnessFail('HARNESS_LIMIT_EXCEEDED', 'benchmark contract artifact exceeds its bound');
    const bytes = Buffer.alloc(before.size);
    let offset = 0;
    while (offset < bytes.length) {
      deadline.checkpoint();
      const { bytesRead } = await handle.read(bytes, offset, Math.min(64 * 1024, bytes.length - offset), offset);
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    const after = await handle.stat();
    if (offset !== before.size || after.size !== before.size || after.mtimeMs !== before.mtimeMs) harnessFail('HARNESS_BUNDLE_INVALID', 'benchmark contract artifact changed while loading');
    return bytes;
  } catch (error) {
    if (error instanceof BenchmarkHarnessError) throw error;
    harnessFail('HARNESS_IO', 'benchmark contract artifact cannot be read', { cause: error });
  } finally { await handle?.close().catch(() => {}); }
}

function setDigest(entries) {
  return sha256(canonicalBytes(entries.map(({ path, sha256: digest }) => ({ path, sha256: digest })).sort((a, b) => codeUnitCompare(a.path, b.path))));
}

async function load(root, options) {
  const manifestBytes = await readBounded(new URL('manifest.json', root), options.maxAssetBytes, options.deadline);
  const manifest = parseJson(manifestBytes, { requireCanonical: true, maxBytes: options.maxAssetBytes });
  const manifestSha256 = sha256(manifestBytes);
  if (manifest.schemaVersion !== 'ogvcs.benchmark/contract-manifest/v1' || manifest.contractVersion !== '1.0.0-rc.1' || manifest.packageName !== PACKAGE || manifest.license !== 'MIT' || !Array.isArray(manifest.artifacts)) harnessFail('HARNESS_BUNDLE_INVALID', 'benchmark contract manifest envelope is invalid');
  if (manifest.artifacts.length !== manifest.counts?.artifacts || manifest.artifacts.length > options.maxArtifacts) harnessFail('HARNESS_LIMIT_EXCEEDED', 'benchmark contract artifact inventory exceeds its bound');
  const artifacts = new Map();
  let totalBytes = manifestBytes.length;
  let retainedBytes = manifestBytes.length * 4 + 128;
  const seen = new Set();
  for (const entry of manifest.artifacts) {
    options.deadline.checkpoint();
    if (!entry || Object.keys(entry).sort().join('\0') !== ['bytes', 'mediaType', 'path', 'sha256'].join('\0') || entry.mediaType !== 'application/json' || !Number.isSafeInteger(entry.bytes) || entry.bytes < 1 || !/^[0-9a-f]{64}$/u.test(entry.sha256) || seen.has(entry.path)) harnessFail('HARNESS_BUNDLE_INVALID', 'benchmark contract artifact inventory is invalid');
    seen.add(entry.path);
    totalBytes = checkedAdd(totalBytes, entry.bytes, 'contract bytes');
    retainedBytes = checkedAdd(retainedBytes, entry.bytes * 4 + 128, 'contract working memory');
    if (totalBytes > options.maxContractBytes || retainedBytes > options.maxWorkingMemoryBytes) harnessFail('HARNESS_LIMIT_EXCEEDED', 'benchmark contract exceeds its configured aggregate bound');
    const bytes = await readBounded(assetUrl(root, entry.path), options.maxAssetBytes, options.deadline);
    if (bytes.length !== entry.bytes || sha256(bytes) !== entry.sha256) harnessFail('HARNESS_BUNDLE_INVALID', `benchmark contract artifact authentication failed: ${entry.path}`);
    artifacts.set(entry.path, parseJson(bytes, { requireCanonical: true, maxBytes: options.maxAssetBytes }));
  }
  if (setDigest(manifest.artifacts) !== manifest.artifactSetSha256 || setDigest(manifest.artifacts.filter(({ path }) => path.startsWith('schemas/'))) !== manifest.schemaSetSha256 || setDigest(manifest.artifacts.filter(({ path }) => path.startsWith('registries/'))) !== manifest.registrySetSha256 || setDigest(manifest.artifacts.filter(({ path }) => path.startsWith('vectors/'))) !== manifest.vectorSetSha256 || setDigest(manifest.artifacts.filter(({ path }) => path.startsWith('thresholds/'))) !== manifest.thresholdSetSha256) harnessFail('HARNESS_BUNDLE_INVALID', 'benchmark contract authority sets do not reproduce');
  const schemas = new Map(); const registries = {}; const profiles = {}; const thresholds = {}; const vectors = {};
  for (const [path, value] of artifacts) {
    if (path.startsWith('schemas/')) schemas.set(path.slice(8), value);
    else if (path.startsWith('registries/')) registries[value.registry] = value;
    else if (path.startsWith('profiles/')) profiles[path.slice(9, -5)] = value;
    else if (path.startsWith('thresholds/')) thresholds[path.slice(11, -5)] = value;
    else if (path.startsWith('vectors/')) vectors[path.slice(8, -5)] = value;
  }
  const limitEntries = Object.fromEntries(registries.limits?.entries?.map(({ name, value }) => [name, value]) ?? []);
  if (canonicalJson(limitEntries) !== canonicalJson(HARNESS_LIMITS)) harnessFail('HARNESS_BUNDLE_INVALID', 'benchmark contract and runtime limit tables differ');
  if (schemas.size !== manifest.counts.schemas || Object.keys(registries).length !== manifest.counts.registries) harnessFail('HARNESS_BUNDLE_INVALID', 'benchmark contract inventory counts differ');
  const validator = new ProtocolSchemaValidator(schemas);
  return deepFreeze({ root: root.href, manifest, manifestSha256, schemas: Object.fromEntries(schemas), registries, profiles, thresholds, vectors, validator, totalBytes, workingMemoryBytes: retainedBytes });
}

export async function loadBenchmarkContract(options = {}) {
  options = snapshotOptions(options, 'benchmark contract options');
  const root = rootUrl(options);
  const settings = {
    deadline: new HarnessDeadline(options),
    maxAssetBytes: boundedInteger(options.maxAssetBytes, 1024 * 1024, 1024 * 1024, 'maxAssetBytes'),
    maxArtifacts: boundedInteger(options.maxArtifacts, 1024, 1024, 'maxArtifacts'),
    maxContractBytes: boundedInteger(options.maxContractBytes, HARNESS_LIMITS.maxResultBundleBytes, HARNESS_LIMITS.maxResultBundleBytes, 'maxContractBytes'),
    maxWorkingMemoryBytes: boundedInteger(options.maxWorkingMemoryBytes, HARNESS_LIMITS.maxWorkingMemoryBytes, HARNESS_LIMITS.maxWorkingMemoryBytes, 'maxWorkingMemoryBytes'),
  };
  const cacheable = options.cache !== false && options.root === undefined && options.maxAssetBytes === undefined && options.maxArtifacts === undefined && options.maxContractBytes === undefined && options.maxWorkingMemoryBytes === undefined;
  if (!cacheable) return load(root, settings);
  if (!defaultContract) defaultContract = load(root, { ...settings, deadline: new HarnessDeadline() }).catch((error) => { defaultContract = undefined; throw error; });
  return settings.deadline.race(defaultContract, 'contract load');
}

export function clearBenchmarkContractCacheForTest() { defaultContract = undefined; }

export function validateBenchmarkValue(contract, selector, value, options = {}) {
  if (!(contract?.validator instanceof ProtocolSchemaValidator)) harnessFail('HARNESS_BUNDLE_INVALID', 'benchmark contract has no schema validator');
  try { return contract.validator.validate(value, selector, options); }
  catch (error) { harnessFail('HARNESS_INPUT_INVALID', 'benchmark value violates its registered schema', { cause: error }); }
}
