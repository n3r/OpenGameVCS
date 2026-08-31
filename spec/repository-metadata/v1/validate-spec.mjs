#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const defaultRoot = dirname(fileURLToPath(import.meta.url));
const profileRefPattern = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*(?:\.[a-z][a-z0-9]*(?:-[a-z0-9]+)*)+\/[a-z][a-z0-9]*(?:-[a-z0-9]+)*@[1-9][0-9]{0,9}$/u;
const allocationReceiptPattern = /^far1\.[A-Za-z0-9_-]{43}$/u;

function digest(bytes) { return createHash('sha256').update(bytes).digest('hex'); }
function assert(condition, message) { if (!condition) throw new Error(message); }
function unique(values) { return new Set(values).size === values.length; }

function profileParts(value) {
  assert(typeof value === 'string' && Buffer.byteLength(value, 'utf8') <= 328 && profileRefPattern.test(value), 'profile reference grammar is invalid');
  const [qualified, majorText] = value.split('@');
  const separator = qualified.lastIndexOf('/');
  return { namespace: qualified.slice(0, separator), id: qualified.slice(separator + 1), major: Number(majorText) };
}

function requireProfileFamily(value, family, profiles) {
  const parts = profileParts(value);
  const selected = profiles.find((entry) => entry.namespace === parts.namespace && entry.id === parts.id && entry.major === parts.major);
  assert(selected?.family === family, `profile reference is not a registered ${family} profile`);
}

function validatePath(parts) {
  assert(Array.isArray(parts) && parts.length <= 256, 'path segment count exceeds contract');
  let bytes = Math.max(0, parts.length - 1);
  for (const part of parts) {
    assert(typeof part === 'string' && part.length > 0 && part.normalize('NFC') === part && part !== '.' && part !== '..' && !part.includes('/') && !part.includes('\0'), 'path segment is invalid');
    const segmentBytes = Buffer.byteLength(part, 'utf8');
    assert(segmentBytes <= 255, 'path segment UTF-8 bytes exceed contract');
    bytes += segmentBytes;
  }
  assert(bytes <= 4_096, 'path UTF-8 bytes exceed contract');
}

export async function validateMetadataOperationSemantics(operation, body, root = defaultRoot) {
  assert(body !== null && typeof body === 'object' && !Array.isArray(body), 'operation body is invalid');
  const workspace = resolve(root, '../../..');
  if (operation === 'repository.create') {
    const features = body.settings?.requiredFeatures;
    assert(Array.isArray(features) && features.every((value, index) => Number.isInteger(value) && value >= 0 && value <= 65_535 && (index === 0 || features[index - 1] < value)), 'requiredFeatures must be sorted and unique');
    const profileDocument = JSON.parse(await readFile(resolve(workspace, 'spec/repository-format/v1/registries/profiles.json')));
    requireProfileFamily(body.settings.pathProfile, 'path', profileDocument.entries);
    requireProfileFamily(body.settings.platformProfile, 'path', profileDocument.entries);
    requireProfileFamily(body.settings.contentPolicyProfile, 'content-policy', profileDocument.entries);
  }
  if (Object.hasOwn(body, 'path')) validatePath(body.path);
  if (Object.hasOwn(body, 'prefix')) validatePath(body.prefix);
  if (operation === 'file-id.register') {
    if (body.origin === 'create' || body.origin === 'copy') {
      assert(typeof body.allocationReceipt === 'string' && allocationReceiptPattern.test(body.allocationReceipt), 'native FileID registration lacks an allocation receipt');
    } else if (body.origin === 'restore') {
      assert(body.allocationReceipt === null, 'restore cannot counterfeit a native allocation receipt');
    }
  }
  return true;
}

export async function validateRepositoryMetadataContract(root = defaultRoot) {
  const manifestBytes = await readFile(resolve(root, 'manifest.json'));
  const manifest = JSON.parse(manifestBytes);
  assert(manifest.schemaVersion === 'ogvcs.repository-metadata/contract-manifest/v1', 'manifest schema is invalid');
  assert(manifest.contractVersion === '0.2.0', 'candidate contract version is invalid');
  assert(manifest.protocolBinding === 'unassigned-future-release-required', 'contract must not claim an R0 protocol binding');

  for (const artifact of manifest.artifacts) {
    const bytes = await readFile(resolve(root, artifact.path));
    assert(bytes.length === artifact.bytes, `artifact length differs: ${artifact.path}`);
    assert(digest(bytes) === artifact.sha256, `artifact authentication failed: ${artifact.path}`);
  }

  const registries = {};
  for (const name of ['operations', 'domain-errors', 'events', 'limits', 'schemas']) {
    registries[name] = JSON.parse(await readFile(resolve(root, 'registries', `${name}.json`)));
    assert(registries[name].registry === name && registries[name].schemaVersion === 'ogvcs.repository-metadata/registry/v1', `invalid registry: ${name}`);
  }

  const operations = registries.operations.entries;
  assert(operations.length === manifest.counts.operations, 'operation count differs');
  assert(unique(operations.map(({ code }) => code)) && unique(operations.map(({ name }) => name)), 'operation assignments are not unique');
  assert(operations.every(({ state, requestSchema }) => state === 'candidate' && requestSchema === 'MetadataOperationRequest.schema.json'), 'operation state/schema differs');
  assert(operations.filter(({ class: kind }) => kind === 'mutation').every(({ idempotencyRequired }) => idempotencyRequired), 'public mutation lacks idempotency requirement');
  assert(operations.filter(({ name }) => name.startsWith('outbox.')).every(({ class: kind, idempotencyRequired }) => kind === 'internal-mutation' && !idempotencyRequired), 'outbox delivery incorrectly became a replay-cache surface');
  assert(operations.filter(({ name }) => name.startsWith('outbox.')).every(({ permission }) => permission === 'service-internal'), 'outbox operation became public permission surface');

  const errors = registries['domain-errors'];
  assert(errors.entries.length === manifest.counts.domainErrors, 'domain-error count differs');
  assert(unique(errors.entries.map(({ code }) => code)) && unique(errors.entries.map(({ name }) => name)), 'domain-error assignments are not unique');
  assert(errors.entries.every(({ protocolBinding, state }) => protocolBinding === 'unassigned' && state === 'candidate'), 'domain error claimed frozen protocol authority');
  assert(errors.entries.every(({ safeParameters }) => safeParameters.every((name) => ['currentGeneration', 'retryAfterMs'].includes(name))), 'domain error has unsafe parameter');
  assert(errors.forbiddenParameters.every((name) => !errors.entries.some(({ safeParameters }) => safeParameters.includes(name))), 'forbidden parameter is exposed');

  const schemas = new Set(registries.schemas.entries.map(({ path }) => path));
  for (const operation of operations) assert(schemas.has(`schemas/${operation.requestSchema}`), `operation schema missing: ${operation.name}`);

  const vectors = JSON.parse(await readFile(resolve(root, 'vectors/contract.json'))).cases;
  assert(vectors.length === manifest.counts.scenarios && unique(vectors.map(({ id }) => id)), 'vector inventory differs');
  const operationNames = new Set(operations.map(({ name }) => name));
  const errorNames = new Set(errors.entries.map(({ name }) => name));
  for (const vector of vectors) {
    assert(operationNames.has(vector.operation), `vector operation is unregistered: ${vector.id}`);
    if (!['accept', 'idempotent'].includes(vector.result)) assert(errorNames.has(vector.result), `vector error is unregistered: ${vector.id}`);
    if (vector.input) await validateMetadataOperationSemantics(vector.operation, vector.input, root);
  }

  const errorSchema = JSON.parse(await readFile(resolve(root, 'schemas/MetadataDomainError.schema.json')));
  assert(errorSchema.oneOf?.length === errors.entries.length, 'domain error schema is not coupled per registry entry');
  for (const [index, entry] of errors.entries.entries()) {
    const variant = errorSchema.oneOf[index];
    assert(variant.properties.code.const === entry.name && variant.properties.numericCode.const === entry.code && variant.properties.retryable.const === entry.retryable, `domain error schema tuple differs: ${entry.name}`);
    assert(JSON.stringify(Object.keys(variant.properties.safeParameters.properties).sort()) === JSON.stringify([...entry.safeParameters].sort()), `domain error safe-parameter set differs: ${entry.name}`);
  }
  const eventSchema = JSON.parse(await readFile(resolve(root, 'schemas/OutboxEvent.schema.json')));
  const resourceRef = eventSchema.properties.resourceRef;
  assert(resourceRef.additionalProperties === false && resourceRef.properties.opaqueId.pattern.startsWith('^rr1') && !Object.hasOwn(resourceRef.properties, 'path') && !Object.hasOwn(resourceRef.properties, 'fileId'), 'outbox resource reference is not opaque and typed');
  const requestSchema = JSON.parse(await readFile(resolve(root, 'schemas/MetadataOperationRequest.schema.json')));
  const requestFor = (name) => requestSchema.oneOf.find((variant) => variant.properties.operation.const === name).properties.body;
  for (const operation of ['repository.get-settings', 'object.get', 'tree.page', 'reference.read', 'reference.list', 'history.ancestry-page', 'history.file-id-page', 'history.path-page', 'file-id.history']) {
    assert(requestFor(operation).properties.minimumConsistencyToken.anyOf[1].pattern.startsWith('^ct1'), `read cannot consume consistency token: ${operation}`);
  }
  assert(!Object.hasOwn(requestFor('consistency.issue-token').properties, 'minimumCommitSequence'), 'public token issue request exposes a commit sequence');
  assert(requestFor('tree.page').properties.cursor.anyOf[1].pattern.startsWith('^cur1'), 'tree cursor accepts a non-cursor token class');
  const registerVariants = requestFor('file-id.register').oneOf;
  assert(registerVariants?.length === 2, 'FileID registration is not split by native/restore proof class');
  const nativeRegistration = registerVariants.find((variant) => variant.properties.origin.enum);
  const restoreRegistration = registerVariants.find((variant) => variant.properties.origin.const === 'restore');
  assert(nativeRegistration.properties.origin.enum.join(',') === 'create,copy', 'native FileID origins differ');
  assert(nativeRegistration.required.includes('allocationReceipt') && nativeRegistration.properties.allocationReceipt.pattern.startsWith('^far1'), 'native FileID registration lacks the opaque allocation receipt');
  assert(restoreRegistration.required.includes('allocationReceipt') && restoreRegistration.properties.allocationReceipt.type === 'null', 'restore can counterfeit the native allocation receipt');
  for (const operation of ['idempotency.status', 'outbox.claim', 'outbox.acknowledge', 'outbox.release']) {
    assert(!JSON.stringify(requestFor(operation)).includes('authenticatedScopeDigest'), `public request exposes authority scope: ${operation}`);
  }

  const allocationSchema = JSON.parse(await readFile(resolve(root, 'schemas/FileIdAllocation.schema.json')));
  assert(allocationSchema.required.includes('allocationReceipt') && allocationSchema.properties.allocationReceipt.pattern.startsWith('^far1'), 'allocation result lacks an opaque receipt');
  assert(!Object.hasOwn(allocationSchema.properties, 'authenticatedScopeDigest'), 'allocation result exposes authority scope');
  const statusSchema = JSON.parse(await readFile(resolve(root, 'schemas/IdempotencyStatus.schema.json')));
  assert(statusSchema.oneOf?.length === 3 && !JSON.stringify(statusSchema).includes('authenticatedScopeDigest'), 'idempotency status is not scope-opaque');
  const pageSchema = JSON.parse(await readFile(resolve(root, 'schemas/PageResult.schema.json')));
  assert(pageSchema.required.includes('operation') && pageSchema.required.includes('consistencyToken'), 'PageResult lacks its public operation/consistency carrier');
  const responseSchema = JSON.parse(await readFile(resolve(root, 'schemas/MetadataHttpResponse.schema.json')));
  assert(responseSchema.oneOf?.length === 6, 'public response carrier branches differ');
  assert(responseSchema.oneOf.some((variant) => variant.properties.carrier?.const === 'page-result' && variant.properties.body?.$ref === 'PageResult.schema.json'), 'public response does not carry PageResult');
  assert(!['path', 'method', 'status', 'mediaType'].some((field) => JSON.stringify(responseSchema).includes(`\"${field}\"`)), 'candidate response carrier claimed an unassigned protocol binding');
  const covered = new Set(vectors.flatMap(({ requirementIds }) => requirementIds));
  for (const [family, count] of [['FR', 9], ['NFR', 3], ['AC', 6]]) {
    for (let index = 1; index <= count; index += 1) {
      const requirement = `OGVCS-006-${family}-${String(index).padStart(2, '0')}`;
      assert(covered.has(requirement), `requirement lacks contract vector: ${requirement}`);
    }
  }

  const workspace = resolve(root, '../../..');
  for (const pin of Object.values(manifest.predecessorPins)) {
    const bytes = await readFile(resolve(workspace, pin.manifestPath));
    assert(digest(bytes) === pin.manifestSha256, `predecessor pin drifted: ${pin.authority}`);
  }

  return Object.freeze({ manifestSha256: digest(manifestBytes), operations: operations.length, errors: errors.entries.length, vectors: vectors.length });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const result = await validateRepositoryMetadataContract();
  process.stdout.write(`validated repository-metadata contract ${result.manifestSha256}: ${result.operations} operations, ${result.errors} domain errors, ${result.vectors} vectors\n`);
}
