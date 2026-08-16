import { open } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

import { parseCanonicalJson, sha256, deepFreeze } from './canonical.mjs';
import { ERROR_CODES, contractError } from './errors.mjs';
import { CONTRACT_VERSION, MANIFEST_SHA256, REGISTRY_ASSIGNMENT_SHA256, REGISTRY_NAMES, REGISTRY_SET_SHA256 } from './generated.mjs';

const PACKAGE = '@opengamevcs/authorization-contract-v1';
const MAX_ASSET_BYTES = 4 * 1024 * 1024;
let cached;

function assetUrl(relativePath) {
  if (!/^(?:manifest\.json|(?:schemas|registries|policies|vectors)\/[A-Za-z0-9._-]+\.json)$/.test(relativePath)) {
    contractError(ERROR_CODES.CONTRACT_INVALID, 'unsafe authorization contract asset path');
  }
  try {
    return new URL(import.meta.resolve(`${PACKAGE}/${relativePath}`));
  } catch (error) {
    contractError(ERROR_CODES.CONTRACT_INVALID, `authorization contract asset is unavailable: ${relativePath}`, { cause: error });
  }
}

async function readBoundedAsset(relativePath) {
  const url = assetUrl(relativePath);
  if (url.protocol !== 'file:') contractError(ERROR_CODES.CONTRACT_INVALID, 'authorization contract asset must be a local file');
  let handle;
  try {
    handle = await open(fileURLToPath(url), 'r');
    const metadata = await handle.stat();
    if (!metadata.isFile() || metadata.size <= 0 || metadata.size > MAX_ASSET_BYTES) {
      contractError(ERROR_CODES.CONTRACT_INVALID, `authorization contract asset is not a bounded regular file: ${relativePath}`);
    }
    const output = Buffer.alloc(metadata.size + 1);
    let offset = 0;
    while (offset < output.length) {
      const { bytesRead } = await handle.read(output, offset, output.length - offset, null);
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    if (offset !== metadata.size) contractError(ERROR_CODES.CONTRACT_INVALID, `authorization contract asset changed while reading: ${relativePath}`);
    const bytes = output.subarray(0, offset);
    return { bytes, text: bytes.toString('utf8'), value: parseCanonicalJson(bytes, { trailingNewline: true, maxBytes: MAX_ASSET_BYTES }) };
  } catch (error) {
    if (error?.code?.startsWith?.('AUTHZ_')) throw error;
    contractError(ERROR_CODES.IO, `cannot read authorization contract asset: ${relativePath}`, { cause: error });
  } finally {
    await handle?.close().catch(() => {});
  }
}

function exactCount(value, expected, label) {
  if (!Number.isSafeInteger(value) || value !== expected) contractError(ERROR_CODES.CONTRACT_INVALID, `${label} count mismatch`);
}

async function load() {
  const manifestAsset = await readBoundedAsset('manifest.json');
  const manifest = manifestAsset.value;
  if (sha256(manifestAsset.bytes) !== MANIFEST_SHA256 || manifest.schemaVersion !== 'ogvcs.authorization/manifest/v1' || manifest.contractVersion !== CONTRACT_VERSION || manifest.registrySetSha256 !== REGISTRY_SET_SHA256) {
    contractError(ERROR_CODES.CONTRACT_INVALID, 'authorization contract manifest authority mismatch');
  }
  exactCount(manifest.schemas, 10, 'schema');
  exactCount(manifest.registries, REGISTRY_NAMES.length, 'registry');
  exactCount(manifest.policies, 2, 'policy');
  exactCount(manifest.decisionVectors, 40, 'decision vector');
  exactCount(manifest.abuseVectors, 30, 'abuse vector');
  exactCount(manifest.grantVectors, 16, 'grant vector');
  if (!Array.isArray(manifest.artifacts) || manifest.artifacts.length !== 31) contractError(ERROR_CODES.CONTRACT_INVALID, 'authorization contract artifact inventory mismatch');

  const seen = new Set();
  const loaded = new Map();
  for (const artifact of manifest.artifacts) {
    if (!artifact || typeof artifact.path !== 'string' || !/^[0-9a-f]{64}$/.test(artifact.sha256) || seen.has(artifact.path)) {
      contractError(ERROR_CODES.CONTRACT_INVALID, 'invalid authorization contract artifact entry');
    }
    seen.add(artifact.path);
    const value = await readBoundedAsset(artifact.path);
    if (sha256(value.bytes) !== artifact.sha256) contractError(ERROR_CODES.CONTRACT_INVALID, `authorization contract artifact digest mismatch: ${artifact.path}`);
    loaded.set(artifact.path, value);
  }

  const registryAssets = [...loaded.entries()].filter(([path]) => path.startsWith('registries/')).sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0);
  const registryInput = Buffer.concat(registryAssets.flatMap(([path, asset]) => [
    Buffer.from(path.slice('registries/'.length), 'utf8'), Buffer.from([0]), asset.bytes,
  ]));
  if (sha256(registryInput) !== REGISTRY_SET_SHA256) contractError(ERROR_CODES.CONTRACT_INVALID, 'authorization registry-set digest mismatch');
  const registries = {};
  const identityFields = {
    'abuse-cases': 'name', 'actor-classes': 'name', 'audit-classes': 'name',
    'credential-classes': 'name', 'data-flows': 'name', 'decision-codes': 'name',
    permissions: 'name', resources: 'name', 'revocation-classes': 'name',
    'roadmap-surfaces': 'prd', 'sandbox-profiles': 'id', threats: 'name',
    'trust-zones': 'name',
  };
  for (const [, asset] of registryAssets) {
    const document = asset.value;
    if (document.schemaVersion !== 'ogvcs.authorization/registry/v1' || document.version !== 1 || !REGISTRY_NAMES.includes(document.registry) || registries[document.registry]) {
      contractError(ERROR_CODES.CONTRACT_INVALID, 'invalid authorization registry envelope');
    }
    const assignments = document.entries.map((entry) => ({
      identity: entry[identityFields[document.registry]],
      code: Number.isInteger(entry.code) ? entry.code : null,
    }));
    if (sha256(Buffer.from(JSON.stringify(assignments), 'utf8')) !== REGISTRY_ASSIGNMENT_SHA256[document.registry]) {
      contractError(ERROR_CODES.CONTRACT_INVALID, `authorization registry assignment drift: ${document.registry}`);
    }
    registries[document.registry] = document;
  }
  if (Object.keys(registries).length !== REGISTRY_NAMES.length) contractError(ERROR_CODES.CONTRACT_INVALID, 'authorization registry inventory mismatch');

  const value = {
    manifest,
    manifestSha256: MANIFEST_SHA256,
    registries,
    policies: {
      'internal-team.json': loaded.get('policies/internal-team.json')?.value,
      'restricted-outsourcer.json': loaded.get('policies/restricted-outsourcer.json')?.value,
    },
    vectors: {
      abuseCatalog: loaded.get('vectors/abuse-catalog.json')?.value,
      authorizedViews: loaded.get('vectors/authorized-views.json')?.value,
      decisions: loaded.get('vectors/decisions.json')?.value,
      goldenRepository: loaded.get('vectors/golden-repository.json')?.value,
      grants: loaded.get('vectors/grants.json')?.value,
      manifest: loaded.get('vectors/manifest.json')?.value,
    },
  };
  if (Object.values(value.policies).some((item) => item === undefined) || Object.values(value.vectors).some((item) => item === undefined)) {
    contractError(ERROR_CODES.CONTRACT_INVALID, 'authorization contract required artifact is absent');
  }
  return deepFreeze(value);
}

export async function loadAuthorizationContract() {
  cached ??= load().catch((error) => {
    cached = undefined;
    throw error;
  });
  return cached;
}

export function clearAuthorizationContractCacheForTest() {
  cached = undefined;
}
