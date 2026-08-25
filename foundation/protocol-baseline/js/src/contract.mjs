import { constants as fsConstants } from 'node:fs';
import { open } from 'node:fs/promises';
import { dirname, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { canonicalBytes, deepFreeze, parseJson, sha256 } from './canonical.mjs';
import { RUNTIME_ERROR_CODES, protocolError } from './errors.mjs';
import { HARD_LIMITS, PROTOCOL_LIMITS_BY_NAME, boundedInteger, deadlineFrom } from './limits.mjs';
import { protocolSchemaValidatorFromAuthenticatedInventory } from './schema.mjs';

const PACKAGE = '@opengamevcs/protocol-contract-v1';
const SAFE_ASSET = /^(?:(?:schemas|registries|profiles)\/[A-Za-z0-9._-]+\.json|vectors\/[A-Za-z0-9._-]+\.(?:json|jsonl)|docs\/[A-Za-z0-9._-]+\.md|LICENSE|README\.md|package\.json)$/u;
const caches = new Map();

function rootUrl(options) {
  if (options.root !== undefined) {
    if (options.root instanceof URL) {
      if (options.root.protocol !== 'file:') protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'protocol contract root must be a local directory');
      return new URL('./', options.root.href.endsWith('/') ? options.root : new URL('.', options.root));
    }
    if (typeof options.root !== 'string' || options.root.length === 0 || options.root.includes('\0')) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'protocol contract root is invalid');
    return pathToFileURL(`${resolve(options.root)}${sep}`);
  }
  try {
    return new URL('./', import.meta.resolve(`${PACKAGE}/manifest.json`));
  } catch (error) {
    protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'installed protocol contract package is unavailable', { cause: error });
  }
}

function assetUrl(root, relativePath) {
  if (!SAFE_ASSET.test(relativePath) || relativePath.includes('..')) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'protocol manifest contains an unsafe artifact path');
  const url = new URL(relativePath, root);
  if (url.protocol !== 'file:' || !url.href.startsWith(root.href)) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'protocol artifact escapes its contract root');
  return url;
}

function setDigest(entries) {
  const records = entries
    .map(({ path, sha256: digest }) => ({ path, sha256: digest }))
    .sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0);
  return sha256(canonicalBytes(records));
}

function expectedMediaType(path) {
  if (path.endsWith('.json')) return 'application/json';
  if (path.endsWith('.jsonl')) return 'application/jsonl';
  if (path.endsWith('.md')) return 'text/markdown; charset=utf-8';
  return 'text/plain; charset=utf-8';
}

async function readBounded(url, label, options, parse = true) {
  const deadline = options.deadline;
  const maxBytes = options.maxAssetBytes;
  let handle;
  try {
    const flags = fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0);
    handle = await deadline.race(open(fileURLToPath(url), flags), `open ${label}`);
    const before = await deadline.race(handle.stat(), `stat ${label}`);
    if (!before.isFile() || before.size <= 0 || before.size > maxBytes) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, `protocol artifact is not a bounded regular file: ${label}`);
    if (options.maxLiveBytes !== undefined && before.size > options.maxLiveBytes) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, `protocol artifact exceeds remaining working memory: ${label}`);
    const output = Buffer.alloc(before.size + 1);
    let offset = 0;
    while (offset < output.length) {
      deadline.checkpoint();
      const { bytesRead } = await deadline.race(handle.read(output, offset, Math.min(64 * 1024, output.length - offset), null), `read ${label}`);
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    const after = await deadline.race(handle.stat(), `restat ${label}`);
    if (offset !== before.size || after.size !== before.size || after.mtimeMs !== before.mtimeMs) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, `protocol artifact changed while reading: ${label}`);
    const bytes = output.subarray(0, offset);
    return { bytes, value: parse ? parseJson(bytes, { requireCanonical: true, maxBytes, deadline }) : undefined };
  } catch (error) {
    if (error?.code?.startsWith?.('PROTOCOL_')) throw error;
    protocolError(RUNTIME_ERROR_CODES.IO, `cannot read protocol artifact: ${label}`, { cause: error });
  } finally {
    if (handle) await handle.close().catch(() => {});
  }
}

function retainedJsonReservation(bytes) {
  // The protocol authority defines the retained canonical-JSON reservation as
  // 128 + four times the encoded byte length. Raw bytes are discarded before
  // the next artifact is retained, so every graph is charged exactly once.
  if (!Number.isSafeInteger(bytes) || bytes < 1 || bytes > Math.floor((Number.MAX_SAFE_INTEGER - 128) / 4)) {
    protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'protocol decoded-graph reservation overflows');
  }
  return bytes * 4 + 128;
}

function registryName(path, value) {
  if (typeof value.registry === 'string' && value.registry.length > 0) return value.registry;
  return path.slice('registries/'.length, -'.json'.length);
}

async function load(root, options) {
  let manifestAsset = await readBounded(new URL('manifest.json', root), 'manifest.json', {
    ...options,
    maxLiveBytes: Math.max(0, Math.floor((options.maxWorkingMemoryBytes - 128) / 4)),
  });
  const manifest = manifestAsset.value;
  const manifestBytes = manifestAsset.bytes.length;
  const manifestSha256 = sha256(manifestAsset.bytes);
  let retainedMemoryBytes = retainedJsonReservation(manifestBytes);
  if (manifestBytes > options.maxContractBytes) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'protocol contract byte ceiling exceeded');
  if (retainedMemoryBytes > options.maxWorkingMemoryBytes) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'protocol manifest exceeds working-memory ceiling');
  manifestAsset = undefined;
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest) || typeof manifest.schemaVersion !== 'string' || !manifest.schemaVersion.startsWith('ogvcs.protocol/')) {
    protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'protocol contract manifest envelope is invalid');
  }
  if (!Array.isArray(manifest.artifacts) || manifest.artifacts.length === 0) {
    protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'protocol contract artifact inventory is invalid');
  }
  if (manifest.artifacts.length > options.maxArtifacts) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'protocol contract artifact ceiling exceeded');
  const seen = new Set();
  const artifacts = new Map();
  let totalBytes = manifestBytes;
  for (const entry of manifest.artifacts) {
    options.deadline.checkpoint();
    if (!entry || typeof entry !== 'object' || Array.isArray(entry) || Object.keys(entry).sort().join('\0') !== ['bytes', 'mediaType', 'path', 'sha256'].join('\0') || typeof entry.path !== 'string' || !Number.isSafeInteger(entry.bytes) || entry.bytes <= 0 || typeof entry.mediaType !== 'string' || entry.mediaType !== expectedMediaType(entry.path) || !/^[0-9a-f]{64}$/u.test(entry.sha256) || seen.has(entry.path)) {
      protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'protocol contract artifact entry is invalid');
    }
    seen.add(entry.path);
    if (entry.bytes > options.maxContractBytes - totalBytes) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, `protocol contract byte ceiling exceeded before reading: ${entry.path}`);
    const parsed = entry.path.endsWith('.json');
    const reservation = parsed ? retainedJsonReservation(entry.bytes) : 0;
    if (retainedMemoryBytes + reservation > options.maxWorkingMemoryBytes) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, `protocol retained graph exceeds working-memory ceiling: ${entry.path}`);
    const asset = await readBounded(assetUrl(root, entry.path), entry.path, {
      ...options,
      maxLiveBytes: parsed ? Math.max(0, Math.floor((options.maxWorkingMemoryBytes - retainedMemoryBytes - 128) / 4)) : options.maxWorkingMemoryBytes - retainedMemoryBytes,
    }, parsed);
    totalBytes += asset.bytes.length;
    if (!Number.isSafeInteger(totalBytes) || totalBytes > options.maxContractBytes) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'protocol contract byte ceiling exceeded');
    if (asset.bytes.length !== entry.bytes || sha256(asset.bytes) !== entry.sha256) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, `protocol artifact digest or length mismatch: ${entry.path}`);
    if (parsed) {
      artifacts.set(entry.path, asset.value);
      retainedMemoryBytes += reservation;
    }
  }

  const schemas = new Map();
  const registries = Object.create(null);
  const vectors = Object.create(null);
  const profiles = Object.create(null);
  for (const [path, value] of artifacts) {
    if (path.startsWith('schemas/')) {
      schemas.set(path.slice('schemas/'.length), value);
    } else if (path.startsWith('registries/')) {
      const name = registryName(path, value);
      if (Object.hasOwn(registries, name)) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'protocol registry name is duplicated');
      registries[name] = value;
    } else if (path.startsWith('vectors/')) {
      if (path.endsWith('.json')) vectors[path.slice('vectors/'.length, -'.json'.length)] = value;
    } else if (path.startsWith('profiles/')) {
      profiles[path.slice('profiles/'.length, -'.json'.length)] = value;
    }
  }
  const inventory = manifest.artifacts;
  const registryEntries = inventory.filter(({ path }) => path.startsWith('registries/'));
  const schemaEntries = inventory.filter(({ path }) => path.startsWith('schemas/'));
  const vectorEntries = inventory.filter(({ path }) => path.startsWith('vectors/'));
  const baseRegistryEntries = registryEntries.filter(({ path }) => path !== 'registries/compatibility.json');
  if (manifest.schemaVersion !== 'ogvcs.protocol/contract-manifest/v1' || manifest.contractVersion !== '1.0.0-rc.1' || manifest.packageName !== PACKAGE || manifest.license !== 'MIT' || manifest.counts?.artifacts !== inventory.length || manifest.counts?.schemas !== schemaEntries.length || manifest.counts?.registries !== registryEntries.length || setDigest(registryEntries) !== manifest.registrySetSha256 || setDigest(schemaEntries) !== manifest.schemaSetSha256 || setDigest(vectorEntries) !== manifest.vectorSetSha256 || setDigest(baseRegistryEntries) !== manifest.negotiationRegistrySetSha256) {
    protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'protocol contract manifest authorities do not reproduce');
  }
  const schemaRegistry = registries.schemas;
  if (schemaRegistry?.registry !== 'schemas' || !Array.isArray(schemaRegistry.entries) || schemaRegistry.entries.length !== schemaEntries.length) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'protocol schema registry is invalid');
  for (const entry of schemaRegistry.entries) {
    const artifact = inventory.find(({ path }) => path === entry.path);
    const schema = artifacts.get(entry.path);
    if (!artifact || artifact.sha256 !== entry.sha256 || schema?.$id !== entry.id || entry.state !== 'candidate') protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'protocol schema registry does not bind its schema set');
  }
  const limitsRegistry = registries.limits;
  if (limitsRegistry?.schemaVersion !== 'ogvcs.protocol/registry/v1' || limitsRegistry.registry !== 'limits' || limitsRegistry.version !== 1 || limitsRegistry.license !== 'MIT' || !Array.isArray(limitsRegistry.entries) || limitsRegistry.entries.length !== Object.keys(PROTOCOL_LIMITS_BY_NAME).length || manifest.counts?.limits !== undefined && manifest.counts.limits !== limitsRegistry.entries.length) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'protocol limits registry is invalid');
  const limitNames = new Set();
  for (const entry of limitsRegistry.entries) {
    const expectedKeys = entry?.name === 'maxErrorParameters'
      ? ['code', 'configuredMinimum', 'enforcement', 'name', 'unit', 'value']
      : ['code', 'enforcement', 'name', 'unit', 'value'];
    if (!entry || typeof entry !== 'object' || Array.isArray(entry) || Object.keys(entry).sort().join('\0') !== expectedKeys.join('\0') || entry.name === 'maxErrorParameters' && entry.configuredMinimum !== 0 || !Number.isSafeInteger(entry.code) || entry.code < 1 || typeof entry.name !== 'string' || !Object.hasOwn(PROTOCOL_LIMITS_BY_NAME, entry.name) || PROTOCOL_LIMITS_BY_NAME[entry.name] !== entry.value || limitNames.has(entry.name)) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'protocol limit assignment does not match the runtime hard ceiling');
    limitNames.add(entry.name);
  }
  for (const registry of Object.values(registries)) {
    if (registry?.schemaVersion !== 'ogvcs.protocol/registry/v1' && registry?.schemaVersion !== 'ogvcs.protocol/field-assignments/v1') protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'protocol registry envelope is invalid');
    const count = Array.isArray(registry.entries) ? registry.entries.length : Array.isArray(registry.messages) ? registry.messages.length : 0;
    if (count > HARD_LIMITS.registryEntries) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'protocol registry-entry ceiling exceeded');
  }
  const vectorCases = Object.entries(vectors).filter(([name]) => name !== 'manifest').reduce((sum, [, document]) => sum + (Array.isArray(document?.cases) ? document.cases.length : 0), 0);
  if (vectorCases !== manifest.counts?.scenarios) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'protocol scenario count does not match the manifest');
  const validator = protocolSchemaValidatorFromAuthenticatedInventory(schemas);
  const contract = {
    manifest,
    manifestSha256,
    root: root.href,
    schemas: Object.fromEntries(schemas),
    registries,
    vectors,
    profiles,
    validator,
    totalBytes,
    workingMemoryBytes: retainedMemoryBytes,
  };
  return deepFreeze(contract);
}

export async function loadProtocolContract(options = {}) {
  const root = rootUrl(options);
  const settings = {
    deadline: deadlineFrom(options),
    maxAssetBytes: boundedInteger(options.maxAssetBytes, HARD_LIMITS.jsonBytes, HARD_LIMITS.jsonBytes, 'maxAssetBytes'),
    maxContractBytes: boundedInteger(options.maxContractBytes, HARD_LIMITS.contractBytes, HARD_LIMITS.contractBytes, 'maxContractBytes'),
    maxArtifacts: boundedInteger(options.maxArtifacts, HARD_LIMITS.manifestArtifacts, HARD_LIMITS.manifestArtifacts, 'maxArtifacts'),
    maxWorkingMemoryBytes: boundedInteger(options.maxWorkingMemoryBytes, HARD_LIMITS.stateBytes, HARD_LIMITS.stateBytes, 'maxWorkingMemoryBytes'),
  };
  if (options.cache === false) return load(root, settings);
  const key = `${root.href}\0${settings.maxAssetBytes}\0${settings.maxContractBytes}\0${settings.maxArtifacts}\0${settings.maxWorkingMemoryBytes}`;
  if (!caches.has(key)) {
    const sharedSettings = { ...settings, deadline: deadlineFrom({ timeoutMs: HARD_LIMITS.timeoutMs }) };
    caches.set(key, load(root, sharedSettings).catch((error) => { caches.delete(key); throw error; }));
  }
  return settings.deadline.race(caches.get(key), 'protocol contract load');
}

export function clearProtocolContractCacheForTest() {
  caches.clear();
}
