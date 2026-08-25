import { constants as fsConstants } from 'node:fs';
import { open } from 'node:fs/promises';
import { resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { base64urlDecode, base64urlEncode, canonicalBytes, cloneJson, deepFreeze, parseJson, sha256 } from './canonical.mjs';
import { RUNTIME_ERROR_CODES, protocolError } from './errors.mjs';
import { HARD_LIMITS, boundedInteger, deadlineFrom } from './limits.mjs';
import {
  ProtocolSchemaValidator,
  protocolSchemaValidatorFromAuthenticatedInventory,
  validateProtocolValue,
} from './schema.mjs';

const AUTHORIZATION_PACKAGE = '@opengamevcs/authorization-contract-v1';
const AUTHORIZATION_PREDECESSOR = Object.freeze({
  contract: 'ogvcs.authorization@1',
  contractVersion: '1.0.0',
  manifestPath: 'spec/authorization/v1/manifest.json',
  manifestSha256: '3fb4dd4a89eb914f93a589b013bda8afcf4744c0d27171ee5849ca3b7bf62447',
  registrySetSha256: '293f9ab0be023a9ded33326d04a8314080bda56e7c70dd18d0cca38b70bed9cc',
});
const REQUIRED_SCHEMAS = Object.freeze([
  'schemas/TransferGrantClaims.schema.json',
  'schemas/TransferGrantEnvelope.schema.json',
]);
const cache = new Map();

function rootUrl(options) {
  if (options.root !== undefined) {
    if (options.root instanceof URL) {
      if (options.root.protocol !== 'file:') protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'authorization contract root must be local');
      return new URL('./', options.root.href.endsWith('/') ? options.root : new URL('.', options.root));
    }
    if (typeof options.root !== 'string' || options.root.length === 0 || options.root.includes('\0')) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'authorization contract root is invalid');
    return pathToFileURL(`${resolve(options.root)}${sep}`);
  }
  try { return new URL('./', import.meta.resolve(`${AUTHORIZATION_PACKAGE}/manifest.json`)); } catch (error) {
    protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'installed authorization contract is unavailable', { cause: error });
  }
}

async function boundedFile(url, maximum, maximumWorking, deadline, label) {
  let handle;
  try {
    handle = await deadline.race(open(fileURLToPath(url), fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0)), `open ${label}`);
    const stat = await deadline.race(handle.stat(), `stat ${label}`);
    if (!stat.isFile() || stat.size <= 0 || stat.size > maximum) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, `${label} is not a bounded regular file`);
    if (stat.size + 1 >= maximumWorking) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, `${label} exceeds remaining working memory`);
    const storage = Buffer.alloc(stat.size + 1);
    let offset = 0;
    while (offset < storage.length) {
      const result = await deadline.race(handle.read(storage, offset, Math.min(64 * 1024, storage.length - offset), null), `read ${label}`);
      if (result.bytesRead === 0) break;
      offset += result.bytesRead;
      deadline.checkpoint();
    }
    const after = await deadline.race(handle.stat(), `restat ${label}`);
    if (offset !== stat.size || after.size !== stat.size || after.mtimeMs !== stat.mtimeMs) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, `${label} changed while reading`);
    const bytes = storage.subarray(0, offset);
    return { bytes, value: parseJson(bytes, {
      trailingNewline: true,
      requireCanonical: true,
      maxBytes: maximum,
      maxWorkingMemoryBytes: maximumWorking - storage.length,
      deadline,
    }) };
  } catch (error) {
    if (error?.code?.startsWith?.('PROTOCOL_')) throw error;
    protocolError(RUNTIME_ERROR_CODES.IO, `cannot read ${label}`, { cause: error });
  } finally {
    if (handle) await handle.close().catch(() => {});
  }
}

async function load(root, options) {
  let manifestAsset = await boundedFile(new URL('manifest.json', root), options.maxAssetBytes, options.maxWorkingMemoryBytes, options.deadline, 'authorization manifest');
  const manifest = manifestAsset.value;
  const manifestSha256 = sha256(manifestAsset.bytes);
  let retainedMemoryBytes = 128 + (4 * manifestAsset.bytes.length);
  let peakWorkingMemoryBytes = retainedMemoryBytes + manifestAsset.bytes.length + 1;
  if (!Number.isSafeInteger(retainedMemoryBytes) || retainedMemoryBytes > options.maxWorkingMemoryBytes) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'authorization manifest exceeds working-memory ceiling');
  manifestAsset = undefined;
  if (manifest?.schemaVersion !== 'ogvcs.authorization/manifest/v1'
    || manifest.contractVersion !== AUTHORIZATION_PREDECESSOR.contractVersion
    || manifest.registrySetSha256 !== AUTHORIZATION_PREDECESSOR.registrySetSha256
    || manifestSha256 !== AUTHORIZATION_PREDECESSOR.manifestSha256
    || !Array.isArray(manifest.artifacts)) {
    protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'authorization manifest envelope is invalid');
  }
  const byPath = new Map();
  for (const entry of manifest.artifacts) {
    if (!entry || typeof entry.path !== 'string' || typeof entry.sha256 !== 'string' || byPath.has(entry.path)) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'authorization manifest inventory is invalid');
    byPath.set(entry.path, entry.sha256);
  }
  const schemas = new Map();
  for (const path of REQUIRED_SCHEMAS) {
    options.deadline.checkpoint();
    const expected = byPath.get(path);
    if (!/^[0-9a-f]{64}$/u.test(expected ?? '')) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, `authorization manifest omits ${path}`);
    let asset = await boundedFile(new URL(path, root), options.maxAssetBytes, options.maxWorkingMemoryBytes - retainedMemoryBytes, options.deadline, path);
    if (sha256(asset.bytes) !== expected) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, `authorization schema digest mismatch: ${path}`);
    const reservation = 128 + (4 * asset.bytes.length);
    if (!Number.isSafeInteger(reservation) || retainedMemoryBytes + reservation > options.maxWorkingMemoryBytes) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, `authorization schema exceeds working-memory ceiling: ${path}`);
    peakWorkingMemoryBytes = Math.max(peakWorkingMemoryBytes, retainedMemoryBytes + asset.bytes.length + 1 + reservation);
    schemas.set(path.slice('schemas/'.length), asset.value);
    retainedMemoryBytes += reservation;
    asset = undefined;
  }
  return deepFreeze({
    manifest,
    manifestSha256,
    registrySetSha256: manifest.registrySetSha256,
    root: root.href,
    validator: protocolSchemaValidatorFromAuthenticatedInventory(schemas),
    schemas: Object.fromEntries(schemas),
    workingMemoryBytes: peakWorkingMemoryBytes,
  });
}

function assertAuthorizationPredecessor(contract, authorizationContract) {
  const pin = contract?.manifest?.predecessorPins?.authorization;
  if (!pin || Object.keys(AUTHORIZATION_PREDECESSOR).some((name) => pin[name] !== AUTHORIZATION_PREDECESSOR[name])
    || authorizationContract?.manifest?.contractVersion !== AUTHORIZATION_PREDECESSOR.contractVersion
    || authorizationContract?.manifestSha256 !== AUTHORIZATION_PREDECESSOR.manifestSha256
    || authorizationContract?.registrySetSha256 !== AUTHORIZATION_PREDECESSOR.registrySetSha256) {
    protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'authorization contract does not match the protocol predecessor pin');
  }
}

export async function loadAuthorizationGrantContract(options = {}) {
  const root = rootUrl(options);
  const settings = {
    maxAssetBytes: boundedInteger(options.maxAssetBytes, 1024 * 1024, HARD_LIMITS.jsonBytes, 'authorization maxAssetBytes'),
    maxWorkingMemoryBytes: boundedInteger(options.maxWorkingMemoryBytes, HARD_LIMITS.stateBytes, HARD_LIMITS.stateBytes, 'maxWorkingMemoryBytes'),
    deadline: deadlineFrom(options),
  };
  if (options.cache === false) return load(root, settings);
  const key = `${root.href}\0${settings.maxAssetBytes}\0${settings.maxWorkingMemoryBytes}`;
  if (!cache.has(key)) {
    const shared = { ...settings, deadline: deadlineFrom({ timeoutMs: HARD_LIMITS.timeoutMs }) };
    cache.set(key, load(root, shared).catch((error) => { cache.delete(key); throw error; }));
  }
  return settings.deadline.race(cache.get(key), 'authorization contract load');
}

export function inspectRequestRootGrant(envelope, authorizationContract, options = {}) {
  if (!(authorizationContract?.validator instanceof ProtocolSchemaValidator)) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'authorization grant schema contract is unavailable');
  const maximum = boundedInteger(options.maxBytes, 32 * 1024, 256 * 1024, 'compact grant maxBytes');
  const value = authorizationContract.validator.validate(envelope, 'TransferGrantEnvelope.schema.json', { ...options, maxBytes: maximum });
  const encoded = canonicalBytes(value, { ...options, maxBytes: maximum });
  const claims = value.claims;
  if (!Array.isArray(claims.objectIds) || claims.objectIds.length !== 0 || typeof claims.requestRoot !== 'string' || !/^sha256:[0-9a-f]{64}$/u.test(claims.requestRoot)) {
    protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'bulk transfer requires a compact request-root grant');
  }
  return deepFreeze({ envelope: value, canonicalJson: encoded.toString('utf8'), sha256: sha256(encoded), registrySetSha256: authorizationContract.registrySetSha256 });
}

export async function validateRequestRootGrant(envelope, authorizationContract, verifyGrant, context, options = {}) {
  if (typeof verifyGrant !== 'function') protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'transfer grant verifier must be callable');
  const deadline = deadlineFrom(options);
  const inspected = inspectRequestRootGrant(envelope, authorizationContract, { ...options, deadline });
  const safeContext = cloneJson(context, { ...options, maxBytes: 16 * 1024, maxDepth: 8, maxNodes: 256, maxStringBytes: 1024, maxCollectionItems: 128, deadline });
  let decision;
  try {
    const supplied = await deadline.race(verifyGrant(inspected.envelope, safeContext, { deadline, signal: deadline.signal }), 'transfer grant verification');
    decision = cloneJson(supplied, { ...options, maxBytes: 1024, maxDepth: 2, maxNodes: 8, maxStringBytes: 128, maxCollectionItems: 4, deadline });
  } catch (error) {
    if ([RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, RUNTIME_ERROR_CODES.DEADLINE_EXCEEDED, RUNTIME_ERROR_CODES.CANCELLED].includes(error?.code)) throw error;
    protocolError(RUNTIME_ERROR_CODES.STATE_CONFLICT, 'transfer grant is invalid', { cause: error });
  }
  if (!decision || typeof decision !== 'object' || Array.isArray(decision)
      || Object.keys(decision).sort().join('\0') !== 'code\0result'
      || decision.result !== 'allow' || decision.code !== 'ALLOW_EXPLICIT') {
    protocolError(RUNTIME_ERROR_CODES.STATE_CONFLICT, 'transfer grant is invalid');
  }
  deadline.checkpoint();
  return inspected;
}

export function createCompactTransferGrant(contract, authorizationContract, envelope, options = {}) {
  if (!contract?.validator) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'protocol contract is unavailable');
  assertAuthorizationPredecessor(contract, authorizationContract);
  const inspected = inspectRequestRootGrant(envelope, authorizationContract, { ...options, maxBytes: HARD_LIMITS.grantBytes });
  const carrier = {
    scheme: 'OGVCS-Grant',
    representation: 'request-root',
    explicitObjectCount: 0,
    envelope: base64urlEncode(Buffer.from(inspected.canonicalJson, 'utf8')),
    authorizationManifestSha256: authorizationContract.manifestSha256,
  };
  return validateProtocolValue(contract, 'CompactTransferGrant.schema.json', carrier, { ...options, maxBytes: HARD_LIMITS.grantBytes });
}

export function decodeCompactTransferGrant(contract, authorizationContract, carrierInput, options = {}) {
  assertAuthorizationPredecessor(contract, authorizationContract);
  const carrier = validateProtocolValue(contract, 'CompactTransferGrant.schema.json', carrierInput, { ...options, maxBytes: HARD_LIMITS.grantBytes });
  if (carrier.authorizationManifestSha256 !== authorizationContract?.manifestSha256 || carrier.explicitObjectCount !== 0 || carrier.representation !== 'request-root') {
    protocolError(RUNTIME_ERROR_CODES.STATE_CONFLICT, 'compact transfer grant authority is invalid');
  }
  let envelope;
  try {
    const bytes = base64urlDecode(carrier.envelope, { maxBytes: HARD_LIMITS.grantBytes });
    envelope = parseJson(bytes, { requireCanonical: true, maxBytes: HARD_LIMITS.grantBytes, deadline: deadlineFrom(options) });
  } catch (error) {
    if (error?.code?.startsWith?.('PROTOCOL_')) throw error;
    protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'compact transfer grant envelope is malformed', { cause: error });
  }
  return inspectRequestRootGrant(envelope, authorizationContract, { ...options, maxBytes: HARD_LIMITS.grantBytes });
}

export async function validateCompactTransferGrant(contract, authorizationContract, carrierInput, verifyGrant, context, options = {}) {
  const inspected = decodeCompactTransferGrant(contract, authorizationContract, carrierInput, options);
  return validateRequestRootGrant(inspected.envelope, authorizationContract, verifyGrant, context, options);
}

export function clearAuthorizationGrantCacheForTest() {
  cache.clear();
}
