import { lstat } from 'node:fs/promises';
import path from 'node:path';

import { canonicalDigest } from './canonical.mjs';
import {
  GENERATOR_VERSION,
  MANIFEST_SCHEMA,
  MAX_GROUP_RELATIONSHIP_BYTES,
  MAX_REQUEST_DOCUMENT_BYTES,
  TOOL_NAME,
} from './constants.mjs';
import { integrityFailure, unsafeDestination } from './errors.mjs';
import { readJson } from './io.mjs';
import { resolveRequest } from './request.mjs';
import { OWNER_FILENAME, rejectSymlinkChain } from './safety.mjs';
import { validateSchemaDocument } from './schema-validator.mjs';

// The largest supported deterministic relationship set is 10,000 groups with
// up to 64 short generated member paths. Keep a pre-parse safety bound while
// leaving conservative headroom for that valid public request domain.
const MAX_MANIFEST_BYTES = MAX_GROUP_RELATIONSHIP_BYTES;
const MAX_OWNER_BYTES = 64 * 1024;
const JSON_PARSE_MEMORY_MULTIPLIER = 8;

function hasExactKeys(value, expectedKeys) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  return actual.length === expected.length
    && actual.every((key, index) => key === expected[index]);
}

export function addManifestDigest(body) {
  return {
    ...body,
    manifestDigest: canonicalDigest(body, 'ogvcs.fixture/manifest/v1'),
  };
}

export async function loadFixtureRequest(destinationPath) {
  const directory = path.resolve(destinationPath);
  await rejectSymlinkChain(directory);
  const directoryMetadata = await lstat(directory).catch(() => null);
  if (!directoryMetadata?.isDirectory() || directoryMetadata.isSymbolicLink()) {
    throw unsafeDestination('Fixture destination is not a real directory', { path: directory });
  }

  const ownerPath = path.join(directory, OWNER_FILENAME);
  const ownerMetadata = await lstat(ownerPath).catch(() => null);
  if (!ownerMetadata?.isFile() || ownerMetadata.isSymbolicLink()) {
    throw unsafeDestination('Fixture destination has no safe generator ownership marker', {
      path: directory,
    });
  }
  if (ownerMetadata.size > MAX_OWNER_BYTES) {
    throw integrityFailure('Fixture ownership marker exceeds its safe byte bound', {
      limit: MAX_OWNER_BYTES,
      path: ownerPath,
      size: ownerMetadata.size,
    });
  }
  const owner = await readJson(ownerPath, 'fixture ownership marker');
  if (
    !hasExactKeys(owner, ['generatorVersion', 'kind', 'requestDigest', 'tool'])
    || owner.kind !== 'opengamevcs-fixture-generator-owned/v1'
    || owner.tool !== TOOL_NAME
    || owner.generatorVersion !== GENERATOR_VERSION
  ) {
    throw integrityFailure('Fixture ownership marker is incompatible or malformed', {
      path: ownerPath,
    });
  }

  const requestPath = path.join(directory, 'fixture-request.json');
  const requestMetadata = await lstat(requestPath).catch(() => null);
  if (!requestMetadata?.isFile() || requestMetadata.isSymbolicLink()) {
    throw integrityFailure('Stored fixture request is missing or unsafe', { path: requestPath });
  }
  if (requestMetadata.size > MAX_REQUEST_DOCUMENT_BYTES) {
    throw integrityFailure('Stored fixture request exceeds its bootstrap byte bound', {
      limit: MAX_REQUEST_DOCUMENT_BYTES,
      path: requestPath,
      size: requestMetadata.size,
    });
  }
  const storedRequest = await readJson(requestPath, 'stored fixture request');
  let request;
  let requestDigest;
  try {
    ({ request, requestDigest } = resolveRequest(storedRequest));
  } catch (error) {
    throw integrityFailure('Stored fixture request is not a valid canonical request', {
      reason: error.message,
    });
  }
  if (owner.requestDigest !== requestDigest) {
    throw integrityFailure('Stored fixture request and ownership marker do not agree');
  }
  return { directory, owner, request, requestDigest };
}

export async function loadManifest(destinationPath, options = {}) {
  const bootstrap = options.bootstrap ?? await loadFixtureRequest(destinationPath);
  const { directory, owner } = bootstrap;
  const manifestPath = path.join(directory, 'manifest.json');
  const manifestMetadata = await lstat(manifestPath).catch(() => null);
  if (!manifestMetadata?.isFile() || manifestMetadata.isSymbolicLink()) {
    throw integrityFailure('Fixture manifest is missing or unsafe', { path: manifestPath });
  }
  if (manifestMetadata.size > MAX_MANIFEST_BYTES) {
    throw integrityFailure('Fixture manifest exceeds its safe byte bound', {
      limit: MAX_MANIFEST_BYTES,
      path: manifestPath,
      size: manifestMetadata.size,
    });
  }
  options.budget?.checkRuntime('manifest-preparse');
  options.budget?.assertMemoryHeadroom?.(
    manifestMetadata.size * JSON_PARSE_MEMORY_MULTIPLIER,
    'manifest-preparse',
  );
  const manifest = await readJson(manifestPath, 'fixture manifest');
  options.budget?.checkRuntime('manifest-postparse');
  const schemaIssues = validateSchemaDocument('FixtureManifest', manifest);
  if (schemaIssues.length > 0) {
    throw integrityFailure('Fixture manifest does not satisfy FixtureManifest.schema.json', {
      issues: schemaIssues.slice(0, 16),
    });
  }
  if (
    manifest.schemaVersion !== MANIFEST_SCHEMA
    || manifest.tool?.name !== TOOL_NAME
    || manifest.tool?.version !== GENERATOR_VERSION
  ) {
    throw integrityFailure('Fixture manifest uses an unsupported schema or generator');
  }
  const { manifestDigest, ...body } = manifest;
  const actualManifestDigest = canonicalDigest(body, 'ogvcs.fixture/manifest/v1');
  if (manifestDigest !== actualManifestDigest) {
    throw integrityFailure('Fixture manifest digest is invalid', {
      actual: actualManifestDigest,
      expected: manifestDigest,
    });
  }
  let request;
  let requestDigest;
  try {
    ({ request, requestDigest } = resolveRequest(manifest.request));
  } catch (error) {
    throw integrityFailure('Fixture manifest contains an invalid request', {
      reason: error.message,
    });
  }
  if (
    requestDigest !== manifest.requestDigest
    || owner.requestDigest !== requestDigest
    || bootstrap.requestDigest !== requestDigest
  ) {
    throw integrityFailure('Stored request, manifest, and ownership marker do not agree');
  }
  return { directory, manifest, request };
}
