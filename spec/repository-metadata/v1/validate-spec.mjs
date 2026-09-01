#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const defaultRoot = dirname(fileURLToPath(import.meta.url));
const profileRefPattern = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*(?:\.[a-z][a-z0-9]*(?:-[a-z0-9]+)*)+\/[a-z][a-z0-9]*(?:-[a-z0-9]+)*@[1-9][0-9]{0,9}$/u;
const allocationReceiptPattern = /^far1\.[A-Za-z0-9_-]{43}$/u;
const objectRefPattern = /^ogvcs:v1:(chunk|content-manifest|tree|change-set|asset-group-set|repository-descriptor|snapshot|shelf-revision|provenance|attestation|conflict-set):sha256:[0-9a-f]{64}$/u;
const metadataObjectKinds = new Set(['content-manifest', 'tree', 'change-set', 'asset-group-set', 'repository-descriptor', 'snapshot', 'provenance', 'attestation', 'conflict-set']);
const metadataProtocolProfile = 'ogvcs.control.https-json@1';
const controlMediaType = 'application/json';
const responseMediaType = 'application/json';
const protocolManifestSha256 = 'bc343842291040b6b0c2c941b183863500c4d60a4618256ffc6e36a1d6afbe72';
const protocolRegistrySetSha256 = '2a49361363cc16e743948fa3cc5e266cd1bc6e31b312cde15b5dab1ad7e5c5b0';
const protocolNegotiationRegistrySetSha256 = '2b1913f9451b9f99966a24942a262846f07662b17cbb41ad6eea6474c23b4352';

function digest(bytes) { return createHash('sha256').update(bytes).digest('hex'); }
function assert(condition, message) { if (!condition) throw new Error(message); }
function unique(values) { return new Set(values).size === values.length; }
function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
  }
  return value;
}

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
    assert(typeof part === 'string'
      && part.length > 0
      && part.normalize('NFC') === part
      && part !== '.'
      && part !== '..'
      && part !== '.ogvcs'
      && !part.includes('/')
      && !part.includes('\\')
      && !/[\u0000-\u001f\u007f]/u.test(part), 'path segment is invalid');
    const segmentBytes = Buffer.byteLength(part, 'utf8');
    assert(segmentBytes <= 255, 'path segment UTF-8 bytes exceed contract');
    bytes += segmentBytes;
  }
  assert(bytes <= 4_096, 'path UTF-8 bytes exceed contract');
}

function validatePersistedIdentifier(value) {
  assert(typeof value === 'string'
    && [...value].length > 0
    && [...value].length <= 256
    && Buffer.byteLength(value, 'utf8') <= 256
    && !value.includes('\0'), 'persisted identifier is invalid');
}

function validateReferenceName(value) {
  assert(typeof value === 'string'
    && [...value].length > 0
    && [...value].length <= 512
    && Buffer.byteLength(value, 'utf8') <= 512
    && !value.includes('\0'), 'reference name is invalid');
}

function objectKind(value) {
  const match = typeof value === 'string' ? objectRefPattern.exec(value) : null;
  assert(match !== null, 'object reference is invalid');
  return match[1];
}

function requireObjectKind(value, expected, field) {
  assert(objectKind(value) === expected, `${field} must be ${expected}`);
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
    requireObjectKind(body.rootSnapshot, 'snapshot', 'rootSnapshot');
    validateReferenceName(body.defaultReference);
  }
  if (Object.hasOwn(body, 'path')) validatePath(body.path);
  if (Object.hasOwn(body, 'prefix')) validatePath(body.prefix);
  if (operation === 'object.put' || operation === 'object.get') {
    assert(metadataObjectKinds.has(objectKind(body.objectRef)), 'object reference is not repository metadata');
  }
  if (operation === 'tree.page') {
    requireObjectKind(body.snapshot, 'snapshot', 'snapshot');
    requireObjectKind(body.tree, 'tree', 'tree');
  }
  if (operation === 'reference.read' || operation === 'reference.compare-and-swap') {
    validateReferenceName(body.referenceName);
  }
  if (operation === 'reference.compare-and-swap') {
    if (body.expected?.state === 'present') requireObjectKind(body.expected.target, 'snapshot', 'expected.target');
    if (body.desired !== null) requireObjectKind(body.desired, 'snapshot', 'desired');
  }
  if (['history.ancestry-page', 'history.file-id-page', 'history.path-page'].includes(operation)) {
    requireObjectKind(body.snapshot, 'snapshot', 'snapshot');
  }
  if (operation === 'file-id.register') {
    if (body.origin === 'create' || body.origin === 'copy') {
      assert(typeof body.allocationReceipt === 'string' && allocationReceiptPattern.test(body.allocationReceipt), 'native FileID registration lacks an allocation receipt');
    } else if (body.origin === 'restore') {
      assert(body.allocationReceipt === null, 'restore cannot counterfeit a native allocation receipt');
    }
  }
  if (operation === 'file-id.register' || operation === 'file-id.register-import') {
    validatePersistedIdentifier(body.ownerId);
  }
  if (operation.startsWith('outbox.')) validatePersistedIdentifier(body.consumerId);
  return true;
}

export function evaluateMetadataTransportVector(vector, bindings) {
  const binding = bindings.find(({ path }) => path === vector.path);
  if (!binding || vector.method !== binding.method) {
    return { admitted: false, result: 'PROTOCOL_MALFORMED' };
  }
  if (!binding.networkRegistered) {
    return { admitted: false, result: 'PROTOCOL_UNSUPPORTED', exposure: binding.exposure };
  }
  if (vector.contentCoding && vector.contentCoding !== 'identity') {
    return { admitted: false, result: 'COMPRESSION_FORBIDDEN' };
  }
  if (vector.redirect === true) return { admitted: false, result: 'REDIRECT_FORBIDDEN' };
  if (vector.requestMediaType !== binding.requestMediaType || vector.accept !== binding.successMediaType) {
    return { admitted: false, result: 'PROTOCOL_UNSUPPORTED' };
  }
  const envelope = vector.control;
  if (envelope === null || typeof envelope !== 'object' || Array.isArray(envelope)) {
    return { admitted: false, result: 'PROTOCOL_MALFORMED' };
  }
  const keys = Object.keys(envelope);
  const allowed = new Set(['schemaVersion', 'operation', 'correlationId', 'deadlineUnixMs', 'negotiationReceipt', 'idempotency', 'body', 'extensions']);
  if (keys.some((key) => !allowed.has(key))
      || envelope.schemaVersion !== 'ogvcs.protocol/request-envelope/v1'
      || envelope.operation !== binding.operation
      || typeof envelope.correlationId !== 'string'
      || envelope.negotiationReceipt?.algorithm !== 'HMAC-SHA-256'
      || envelope.body === undefined) {
    return { admitted: false, result: 'PROTOCOL_MALFORMED' };
  }
  return {
    admitted: true,
    status: binding.successStatus,
    ...(binding.stream !== 'none' ? { stream: binding.stream } : { stream: 'none' }),
    ...(binding.exposure === 'atomic-create-coordinator' ? { exposure: binding.exposure } : {}),
  };
}

export async function validateRepositoryMetadataContract(root = defaultRoot) {
  const manifestBytes = await readFile(resolve(root, 'manifest.json'));
  const manifest = JSON.parse(manifestBytes);
  assert(manifest.schemaVersion === 'ogvcs.repository-metadata/contract-manifest/v1', 'manifest schema is invalid');
  assert(manifest.contractVersion === '0.3.0', 'candidate contract version is invalid');
  assert(manifest.protocolBinding === metadataProtocolProfile, 'metadata protocol profile binding differs');

  for (const artifact of manifest.artifacts) {
    const bytes = await readFile(resolve(root, artifact.path));
    assert(bytes.length === artifact.bytes, `artifact length differs: ${artifact.path}`);
    assert(digest(bytes) === artifact.sha256, `artifact authentication failed: ${artifact.path}`);
  }

  const registries = {};
  for (const name of ['operations', 'domain-errors', 'events', 'limits', 'protocol-bindings', 'schemas']) {
    registries[name] = JSON.parse(await readFile(resolve(root, 'registries', `${name}.json`)));
    assert(registries[name].registry === name && registries[name].schemaVersion === 'ogvcs.repository-metadata/registry/v1', `invalid registry: ${name}`);
  }

  const operations = registries.operations.entries;
  assert(operations.length === manifest.counts.operations, 'operation count differs');
  assert(unique(operations.map(({ code }) => code)) && unique(operations.map(({ name }) => name)), 'operation assignments are not unique');
  assert(operations.every(({ state, requestEnvelopeSchema, requestEnvelopeSha256, bodyProjectionSchema }) => state === 'candidate'
    && requestEnvelopeSchema === 'schemas/RequestEnvelope.schema.json'
    && requestEnvelopeSha256 === '740fc71a4ba1e480076b8b6d3fc8bb5b5374e86157976747795a139694bbadd9'
    && bodyProjectionSchema === 'MetadataOperationBodyProjection.schema.json'), 'operation envelope/body schema differs');
  assert(operations.filter(({ class: kind }) => kind === 'mutation').every(({ idempotencyRequired }) => idempotencyRequired), 'public mutation lacks idempotency requirement');
  assert(operations.filter(({ name }) => name.startsWith('outbox.')).every(({ class: kind, idempotencyRequired }) => kind === 'internal-mutation' && !idempotencyRequired), 'outbox delivery incorrectly became a replay-cache surface');
  assert(operations.filter(({ name }) => name.startsWith('outbox.')).every(({ permission }) => permission === 'service-internal'), 'outbox operation became public permission surface');

  const errors = registries['domain-errors'];
  assert(errors.entries.length === manifest.counts.domainErrors, 'domain-error count differs');
  assert(unique(errors.entries.map(({ code }) => code)) && unique(errors.entries.map(({ name }) => name)), 'domain-error assignments are not unique');
  assert(errors.entries.every(({ protocolBinding, wireSurface, state }) => protocolBinding === null
    && wireSurface === 'internal-unassigned' && state === 'candidate'), 'unassigned domain error became a protocol ProblemDetails code');
  assert(errors.entries.every(({ safeParameters }) => safeParameters.every((name) => ['currentGeneration', 'retryAfterMs'].includes(name))), 'domain error has unsafe parameter');
  assert(errors.forbiddenParameters.every((name) => !errors.entries.some(({ safeParameters }) => safeParameters.includes(name))), 'forbidden parameter is exposed');

  const schemas = new Set(registries.schemas.entries.map(({ path }) => path));
  for (const operation of operations) assert(schemas.has(`schemas/${operation.bodyProjectionSchema}`), `operation body projection schema missing: ${operation.name}`);

  const vectors = JSON.parse(await readFile(resolve(root, 'vectors/contract.json'))).cases;
  const protocolVectors = JSON.parse(await readFile(resolve(root, 'vectors/protocol.json'))).cases;
  assert(vectors.length + protocolVectors.length === manifest.counts.scenarios
    && unique([...vectors, ...protocolVectors].map(({ id }) => id)), 'vector inventory differs');
  const operationNames = new Set(operations.map(({ name }) => name));
  const errorNames = new Set(errors.entries.map(({ name }) => name));
  for (const vector of vectors) {
    assert(operationNames.has(vector.operation), `vector operation is unregistered: ${vector.id}`);
    if (!['accept', 'idempotent'].includes(vector.result)) assert(errorNames.has(vector.result), `vector error is unregistered: ${vector.id}`);
    if (vector.input) await validateMetadataOperationSemantics(vector.operation, vector.input, root);
  }

  const transport = registries['protocol-bindings'];
  assert(transport.profile.id === metadataProtocolProfile
    && transport.profile.requestMediaType === controlMediaType
    && transport.profile.responseMediaType === responseMediaType
    && transport.profile.errorMediaType === responseMediaType
    && transport.profile.requestEnvelopeSchemaVersion === 'ogvcs.protocol/request-envelope/v1'
    && transport.profile.responseEnvelopeSchemaVersion === 'ogvcs.protocol/response-envelope/v1'
    && transport.profile.authority.manifestSha256 === protocolManifestSha256
    && transport.profile.authority.registrySetSha256 === protocolRegistrySetSha256
    && transport.profile.authority.negotiationRegistrySetSha256 === protocolNegotiationRegistrySetSha256
    && transport.profile.authority.controlProfileSha256 === '3934506ee6d21005dc4b9b91e924e33601de3ade5417e4393a8acb8178bb36f9'
    && transport.profile.authority.requestEnvelopeSha256 === '740fc71a4ba1e480076b8b6d3fc8bb5b5374e86157976747795a139694bbadd9'
    && transport.profile.authority.responseEnvelopeSha256 === '47792190106b0742af4245c69eff3eb9d6e9555c557b16f23fae3d12d8790900'
    && transport.profile.authority.problemDetailsSha256 === 'deba5763c47a54e23489d427eb094fa905fadfa81806a3e2da5f752501dfb6a1'
    && transport.profile.authority.errorRegistrySha256 === '2801e26224536b8b9f2072324d25c6b472274ce45135bd65e6e9e11a643a922f'
    && transport.profile.contentCoding === 'identity'
    && transport.profile.redirects === 'forbidden', 'transport profile differs');
  assert(transport.entries.length === operations.length
    && unique(transport.entries.map(({ path }) => path))
    && unique(transport.entries.map(({ code }) => code)), 'transport assignments are not one-to-one');
  for (const [index, binding] of transport.entries.entries()) {
    const operation = operations[index];
    assert(binding.code === operation.code && binding.operation === operation.name
      && binding.method === 'POST'
      && binding.path === `/v1/repository-metadata/operations/${operation.name}`
      && binding.profile === metadataProtocolProfile
      && binding.requestMediaType === controlMediaType
      && binding.errorMediaType === responseMediaType
      && binding.state === 'candidate', `transport tuple differs: ${operation.name}`);
    assert(binding.requiredCapabilities.includes('ogvcs.control.https-json@1')
      && binding.requiredCapabilities.includes('ogvcs.protocol.schema@1')
      && binding.requiredCapabilities.includes('ogvcs.authorization@1')
      && binding.requiredCapabilities.includes('ogvcs.receipt.hmac-sha256@1'), `transport capabilities differ: ${operation.name}`);
    assert(!/[{}]/u.test(binding.path), `protected identifier entered route template: ${operation.name}`);
    assert(binding.networkRegistered === false,
      `v0.3 network registration must remain empty: ${operation.name}`);
    if (binding.exposure === 'stream-carrier-required') {
      assert(binding.stream === 'carrier-unassigned-closed', `unassigned stream route became usable: ${operation.name}`);
    }
  }
  const expectedNetworkRoutes = transport.entries
    .filter(({ networkRegistered }) => networkRegistered)
    .map(({ code, operation, method, path }) => ({ code, operation, method, path }));
  assert(JSON.stringify(canonical(transport.networkRoutes)) === JSON.stringify(canonical(expectedNetworkRoutes)),
    'network route inventory differs from registered bindings');
  assert(transport.networkRoutes.length === 0, 'v0.3 cannot claim an unwired production route');
  assert(transport.networkRoutes.every(({ operation }) => {
    const binding = transport.entries.find((entry) => entry.operation === operation);
    return binding && !['internal-only', 'aggregate-coordinator-required', 'stream-carrier-required', 'atomic-create-coordinator', 'project-authority-required'].includes(binding.exposure);
  }), 'closed operation entered the network route inventory');
  for (const vector of protocolVectors) {
    assert(JSON.stringify(canonical(evaluateMetadataTransportVector(vector, transport.entries)))
      === JSON.stringify(canonical(vector.expected)), `transport vector differs: ${vector.id}`);
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
  const requestSchema = JSON.parse(await readFile(resolve(root, 'schemas/MetadataOperationBodyProjection.schema.json')));
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
  const responseSchema = JSON.parse(await readFile(resolve(root, 'schemas/MetadataResultBody.schema.json')));
  assert(responseSchema.oneOf?.length === 4, 'domain success body branches differ');
  assert(responseSchema.oneOf.some((variant) => variant.properties.carrier?.const === 'page-result' && variant.properties.body?.$ref === 'PageResult.schema.json'), 'public response does not carry PageResult');
  assert(!JSON.stringify(responseSchema).includes('domain-error')
    && !['path', 'method', 'status', 'mediaType', 'correlationId', 'problem'].some((field) => JSON.stringify(responseSchema).includes(`\"${field}\"`)), 'domain result body attempted to replace OGVCS-041 ResponseEnvelope/ProblemDetails');
  const covered = new Set(vectors.flatMap(({ requirementIds }) => requirementIds));
  for (const [family, count] of [['FR', 9], ['NFR', 3], ['AC', 6]]) {
    for (let index = 1; index <= count; index += 1) {
      const requirement = `OGVCS-006-${family}-${String(index).padStart(2, '0')}`;
      assert(covered.has(requirement), `requirement lacks contract vector: ${requirement}`);
    }
  }

  const workspace = resolve(root, '../../..');
  const protocolManifest = await readFile(resolve(workspace, 'spec/protocols/v1/manifest.json'));
  assert(digest(protocolManifest) === protocolManifestSha256, 'OGVCS-041 manifest pin drifted');
  const protocolAuthority = JSON.parse(protocolManifest);
  assert(protocolAuthority.registrySetSha256 === protocolRegistrySetSha256
    && protocolAuthority.negotiationRegistrySetSha256 === protocolNegotiationRegistrySetSha256,
  'OGVCS-041 registry-set pins differ');
  assert(manifest.predecessorPins.protocol.registrySetSha256 === protocolRegistrySetSha256
    && manifest.predecessorPins.protocol.negotiationRegistrySetSha256 === protocolNegotiationRegistrySetSha256,
  'metadata manifest does not name both OGVCS-041 registry-set identities');
  for (const [path, expected] of [
    ['profiles/control-https-json-v1.json', transport.profile.authority.controlProfileSha256],
    ['schemas/RequestEnvelope.schema.json', transport.profile.authority.requestEnvelopeSha256],
    ['schemas/ResponseEnvelope.schema.json', transport.profile.authority.responseEnvelopeSha256],
    ['schemas/ProblemDetails.schema.json', transport.profile.authority.problemDetailsSha256],
    ['registries/error-codes.json', transport.profile.authority.errorRegistrySha256],
  ]) {
    assert(digest(await readFile(resolve(workspace, 'spec/protocols/v1', path))) === expected,
      `OGVCS-041 authority artifact drifted: ${path}`);
  }
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
