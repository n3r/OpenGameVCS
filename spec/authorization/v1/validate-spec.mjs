#!/usr/bin/env node

import { createHash, createPublicKey, verify } from 'node:crypto';
import { lstat, readFile, readdir } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = resolve(ROOT, '../../..');
const MAX_JSON_BYTES = 4 * 1024 * 1024;
const MAX_DEPTH = 32;
const MAX_NODES = 200000;
const GRANT_DOMAIN = Buffer.from('OGVCS-AUTH-GRANT-V1\0', 'ascii');
const REQUEST_ROOT_DOMAIN = Buffer.from('OGVCS-AUTH-REQUEST-ROOT-V1\0', 'ascii');
const EXPECTED = Object.freeze({ schemas: 10, registries: 13, policies: 2, decisionVectors: 40, abuseVectors: 30, grantVectors: 16, roadmapPrds: 45 });
const EXPECTED_REGISTRIES = new Set([
  'abuse-cases', 'actor-classes', 'audit-classes', 'credential-classes',
  'data-flows', 'decision-codes', 'permissions', 'resources',
  'revocation-classes', 'roadmap-surfaces', 'sandbox-profiles', 'threats',
  'trust-zones',
]);
const REGISTRY_IDENTITY_FIELDS = Object.freeze({
  'abuse-cases': 'name',
  'actor-classes': 'name',
  'audit-classes': 'name',
  'credential-classes': 'name',
  'data-flows': 'name',
  'decision-codes': 'name',
  permissions: 'name',
  resources: 'name',
  'revocation-classes': 'name',
  'roadmap-surfaces': 'prd',
  'sandbox-profiles': 'id',
  threats: 'name',
  'trust-zones': 'name',
});
const EXPECTED_ASSIGNMENT_SHA256 = Object.freeze({
  'abuse-cases': '52237777ae4f35dbadd32a083044ea8427fd1af93810d73b7ac9d47487a5b480',
  'actor-classes': '7266bc679dbf48a9abb31a836f092dc89cd9389c9d177b8cfc17b4e66453e051',
  'audit-classes': '1d980aeaa6c2c5aa09e02e1ed4ee2e4ce9b965922fa9aa9fcc5f3100c37892a6',
  'credential-classes': '4904f7289ec8e8cb6bae3c440ccc0be7fc5d87b128052b76991dff7f53905650',
  'data-flows': 'a947403eaec6edffe0bfc13f3129e9f9c54ecd67cbffbd1880355fda6d70abd5',
  'decision-codes': '6f620d77a770fcd712f84406b87b7e29a3b2961b193e4c582c69f2e0ea8fb2ca',
  permissions: 'cb1e3c5f77ea6f1b6e0e6e525d3b448568aebdfb2f5f3149b40b583fd5b08cea',
  resources: 'edf5a2c65bb8e68b1ef7ba4680e8337bb8b86b7d0504c392eddc52365a55eb0a',
  'revocation-classes': 'cbebc25ba6f225424324ab51c05155b123c7fd74c2e6bf5681ae59847dab23b5',
  'roadmap-surfaces': 'e19a3aeb34192dc92aa15a6eee8cfaaf34bd5b870df031471b87585e4e26486c',
  'sandbox-profiles': '5128f9f2fead30eaf6f4baf1a7206b56dcc8d41eeb44ef236ee25f5e57bcae4a',
  threats: 'f03d7eb38a01a6d0d1ff2a5dcfaad9fd83daa43765c261f93374a3e5d025c158',
  'trust-zones': '5904c5045fb64468fcf6864bb0333ee79a0c265a1b0357a080035b97fd63a43a',
});
const EXPECTED_REGISTRY_DOCUMENT_SHA256 = Object.freeze({
  'abuse-cases': '7ea952d1c28ff13bd58022654e5813cd83f910cff34e420e8be26fea6e650366',
  'actor-classes': '1019888338ee28ad5e6137722d94d674b391eed18fd6a11fc60a5d2b2088ebf9',
  'audit-classes': 'f0fe961ecbd65abd5cd2dbd596565c585bee958464b6c7ba7593e17524175f9e',
  'credential-classes': '6e4ef55836374aaf7e5a02a1ffd984e00f20ae39d7ddd98c1609129507f60f2b',
  'data-flows': '6bb9fbd679a8c0fdb655d63370a196091e054efe4307d87b5938eb67a4234e40',
  'decision-codes': '6a951026ea80837b54e5da3601fc28387d0a99804f9ddc330d8b8b1c6802e1d0',
  permissions: 'b69ccb68e38c33898e327ff0f8ae04efe1f7465f9d411de06912354726f1f591',
  resources: '97ec3aa14b414b3961afe9b9128f3865f2324a9aa3f198a1d6e70c05169dd05b',
  'revocation-classes': '4d9c149b6050f719105d96b7e2c3afcf0c20a99dbe29fc7a3933b6bfa9256864',
  'roadmap-surfaces': 'f396f9e39512de93ebdbc16bc01b0995aeb7437293eacf18d6f53c3383638734',
  'sandbox-profiles': '32a90e3e97ea9b3b38664d78115458447f8e8907d16ef02aa430511ded6b3779',
  threats: 'db020edcb11b3de00b66564cbf6a5c664fe205915327d2029ed61680d0f7f9d7',
  'trust-zones': '4160222dc3e844d9df8751c5d22bac5c501a2aabefe0d94f45955fbec21b3f3c',
});
const REQUIRED_PERMISSIONS = new Set([
  'discover', 'metadata.read', 'content.materialize', 'content.upload',
  'lock.create', 'submit', 'review', 'export', 'policy.administer',
  'lock.force-unlock', 'repair', 'retention.delete', 'audit.read', 'impersonate',
]);
const PRIVILEGED_PERMISSIONS = new Set([
  'export', 'policy.administer', 'lock.force-unlock', 'repair',
  'retention.delete', 'audit.read', 'impersonate',
]);
const REQUIRED_ABUSE_CATEGORIES = new Set([
  'guessed-hash', 'cache-replay', 'mixed-visibility-history',
  'mixed-visibility-review', 'search', 'events', 'export',
  'deduplication-probe', 'hook-escape', 'preview-escape', 'token-revocation',
]);
const REQUIRED_THREAT_ACTORS = new Set([
  'external-attacker', 'malicious-user', 'compromised-user', 'administrator',
  'build-identity', 'cache-operator', 'hostile-import-file', 'plugin', 'hook',
  'preview-parser', 'stolen-device', 'confused-deputy-service',
]);
const REQUIRED_FORBIDDEN_FIELDS = new Set([
  'path', 'fileId', 'objectId', 'size', 'hash', 'history', 'message', 'thumbnail',
  'dependency', 'lockOwner', 'branch', 'searchHit', 'event', 'policy', 'claims',
]);

function fail(message) {
  throw new Error(`authorization-contract-v1: ${message}`);
}

function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'number' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  fail('value outside canonical JSON domain');
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function requestRootForObjectIds(objectIds) {
  return `sha256:${sha256(Buffer.concat([
    REQUEST_ROOT_DOMAIN,
    Buffer.from(canonicalJson([...objectIds].sort()), 'utf8'),
  ]))}`;
}

function inspectTree(value, label) {
  const stack = [{ value, depth: 0 }];
  let nodes = 0;
  while (stack.length > 0) {
    const current = stack.pop();
    nodes += 1;
    if (nodes > MAX_NODES) fail(`${label} exceeds node ceiling`);
    if (current.depth > MAX_DEPTH) fail(`${label} exceeds depth ceiling`);
    if (typeof current.value === 'string' && Buffer.byteLength(current.value, 'utf8') > 65536) {
      fail(`${label} contains oversized string`);
    }
    if (Array.isArray(current.value)) {
      for (const child of current.value) stack.push({ value: child, depth: current.depth + 1 });
    } else if (current.value && typeof current.value === 'object') {
      for (const [key, child] of Object.entries(current.value)) {
        if (Buffer.byteLength(key, 'utf8') > 256) fail(`${label} contains oversized key`);
        stack.push({ value: child, depth: current.depth + 1 });
      }
    } else if (current.value !== null && !['string', 'number', 'boolean'].includes(typeof current.value)) {
      fail(`${label} contains unsupported value`);
    }
  }
}

async function loadCanonical(relativePath) {
  const absolute = resolve(ROOT, relativePath);
  const metadata = await lstat(absolute);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > MAX_JSON_BYTES) {
    fail(`${relativePath} is not a bounded regular file`);
  }
  const text = await readFile(absolute, 'utf8');
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    fail(`${relativePath} is invalid JSON`);
  }
  inspectTree(value, relativePath);
  if (`${canonicalJson(value)}\n` !== text) fail(`${relativePath} is not canonical JSON`);
  return { value, text };
}

function exactSet(actual, expected, label) {
  if (actual.size !== expected.size || [...expected].some((value) => !actual.has(value))) {
    fail(`${label} does not match frozen set`);
  }
}

function unique(values, label) {
  if (new Set(values).size !== values.length) fail(`${label} contains duplicates`);
}

function segmentPrefix(path, prefix) {
  return prefix === '' || path === prefix || path.startsWith(`${prefix}/`);
}

function matches(rule, request) {
  if (rule.actors.length > 0 && !rule.actors.includes(request.actor.id)) return false;
  if (rule.groups.length > 0 && !rule.groups.some((group) => request.actor.groups.includes(group))) return false;
  if (rule.actorClasses.length > 0 && !rule.actorClasses.includes(request.actor.class)) return false;
  if (!rule.tenants.includes(request.tenant) || !rule.repositories.includes(request.repository)) return false;
  if (rule.references.length > 0 && !rule.references.includes(request.context.reference)) return false;
  if (rule.pathPrefixes.length > 0 && (
    typeof request.resource.path !== 'string' ||
    !rule.pathPrefixes.some((prefix) => segmentPrefix(request.resource.path, prefix))
  )) return false;
  return rule.resourceTypes.includes(request.resource.type) && rule.permissions.includes(request.permission);
}

function independentDecision(policy, request, permissionIndex) {
  let code;
  if (request.context.policyGeneration !== policy.policyGeneration) code = 'DENY_POLICY_GENERATION_MISMATCH';
  else if (request.context.authorityEpoch !== policy.authorityEpoch || request.actor.authorityEpoch !== policy.authorityEpoch || request.actor.credentialStatus !== 'active') code = 'DENY_EPOCH_STALE';
  else if (permissionIndex.get(request.permission)?.reasonRequired && (typeof request.reason !== 'string' || request.reason.trim() === '')) code = 'DENY_PRIVILEGED_REASON_REQUIRED';
  else {
    const matching = policy.rules.filter((rule) => matches(rule, request));
    if (matching.some(({ effect }) => effect === 'deny')) code = 'DENY_NOT_AUTHORIZED';
    else if (matching.some(({ effect }) => effect === 'allow')) code = 'ALLOW_EXPLICIT';
    else code = 'DENY_NOT_AUTHORIZED';
  }
  const allowed = code.startsWith('ALLOW_');
  const fingerprint = sha256(Buffer.from(canonicalJson({
    policy: { id: policy.id, version: policy.version, policyGeneration: policy.policyGeneration },
    request,
  }), 'utf8'));
  return { allowed, code, fingerprint };
}

function independentGrantResult(testCase, publicJwk) {
  const { envelope, context } = testCase;
  let validSignature = false;
  try {
    validSignature = verify(null, Buffer.concat([
      GRANT_DOMAIN,
      Buffer.from(canonicalJson(envelope.claims), 'utf8'),
    ]), createPublicKey({ key: publicJwk, format: 'jwk' }), Buffer.from(envelope.signature, 'base64url'));
  } catch {
    validSignature = false;
  }
  if (!validSignature || envelope.algorithm !== 'Ed25519' || envelope.keyId !== envelope.claims.keyId) return 'DENY_GRANT_INVALID';
  const claims = envelope.claims;
  if (claims.authorityEpoch !== context.authorityEpoch || claims.keyGeneration !== context.keyGeneration || claims.keyId !== context.keyId) return 'DENY_EPOCH_STALE';
  if (context.now < claims.issuedAt || context.now >= claims.expiresAt) return 'DENY_GRANT_EXPIRED';
  if (claims.audience !== context.audience) return 'DENY_AUDIENCE_MISMATCH';
  if (claims.issuer !== context.issuer || claims.subject !== context.subject || claims.permission !== context.permission || claims.operation !== context.operation || claims.tenant !== context.tenant || claims.repository !== context.repository) return 'DENY_RESOURCE_SCOPE';
  if (claims.requestRoot === null
    ? context.requestObjectIds.length !== 0 || !claims.objectIds.includes(context.objectId)
    : !context.requestObjectIds.includes(context.objectId) || requestRootForObjectIds(context.requestObjectIds) !== claims.requestRoot) return 'DENY_RESOURCE_SCOPE';
  if (claims.replay === 'single-use' && context.consumedNonces.includes(claims.nonce)) return 'DENY_GRANT_REPLAY';
  return 'ALLOW_EXPLICIT';
}

async function listedJson(directory) {
  const entries = await readdir(resolve(ROOT, directory), { withFileTypes: true });
  return entries.filter((entry) => entry.isFile() && entry.name.endsWith('.json')).map(({ name }) => `${directory}/${name}`).sort();
}

const manifest = (await loadCanonical('manifest.json')).value;
if (manifest.schemaVersion !== 'ogvcs.authorization/manifest/v1' || manifest.contractVersion !== '1.0.0') fail('manifest version mismatch');
for (const [name, expected] of Object.entries(EXPECTED)) {
  if (name === 'roadmapPrds') continue;
  if (manifest[name] !== expected) fail(`manifest ${name} mismatch`);
}
unique(manifest.artifacts.map(({ path }) => path), 'manifest paths');
const actualArtifacts = [
  ...await listedJson('schemas'),
  ...await listedJson('registries'),
  ...await listedJson('policies'),
  ...await listedJson('vectors'),
].sort();
exactSet(new Set(manifest.artifacts.map(({ path }) => path)), new Set(actualArtifacts), 'artifact inventory');
for (const artifact of manifest.artifacts) {
  const loaded = await loadCanonical(artifact.path);
  if (sha256(loaded.text) !== artifact.sha256) fail(`artifact digest mismatch: ${artifact.path}`);
}

const schemaFiles = await listedJson('schemas');
if (schemaFiles.length !== EXPECTED.schemas) fail('schema inventory mismatch');
const schemas = new Map();
for (const path of schemaFiles) {
  const schema = (await loadCanonical(path)).value;
  const name = path.slice('schemas/'.length);
  if (schema.$schema !== 'https://json-schema.org/draft/2020-12/schema' ||
      schema.$id !== `https://schemas.opengamevcs.org/authorization/v1/${name}` ||
      schema.type !== 'object' || schema.additionalProperties !== false ||
      !Array.isArray(schema.required) || !schema.properties) {
    fail(`invalid closed JSON Schema: ${name}`);
  }
  schemas.set(name, schema);
}
const diagnosticPattern = '^[A-Z][A-Z0-9_]*$';
if (schemas.get('RunnerReport.schema.json').properties.rows.items.properties.expectedCode.pattern !== diagnosticPattern ||
    schemas.get('RunnerReport.schema.json').properties.rows.items.properties.actualCode.pattern !== diagnosticPattern) {
  fail('diagnostic code grammar is not frozen');
}
if (schemas.get('TransferGrantEnvelope.schema.json').properties.claims.$ref !==
    'https://schemas.opengamevcs.org/authorization/v1/TransferGrantClaims.schema.json') {
  fail('transfer-grant envelope does not bind the claims schema');
}
if (schemas.get('TransferGrantContext.schema.json').properties.requestObjectIds.maxItems !== 32_768 || schemas.get('TransferGrantContext.schema.json').properties.consumedNonces.maxItems !== 4096) {
  fail('transfer-grant context bounds are not frozen');
}
if (schemas.get('TransferGrantClaims.schema.json')['x-ogvcs-maxValiditySeconds'] !== 300) fail('transfer-grant validity ceiling is not frozen');
if (schemas.get('ThreatVector.schema.json').properties.forbiddenResponseFields.items.pattern !==
    '^[A-Za-z][A-Za-z0-9.-]*$') {
  fail('forbidden response field grammar is not frozen');
}
const requestPathSchema = schemas.get('AuthorizationRequest.schema.json').properties.resource.properties.path.oneOf[1];
if (requestPathSchema['x-ogvcs-maxUtf8Bytes'] !== 4096 || requestPathSchema['x-ogvcs-maxSegments'] !== 256 || requestPathSchema['x-ogvcs-maxSegmentUtf8Bytes'] !== 255) {
  fail('authorization path hard limits are not frozen');
}

const registryFiles = await listedJson('registries');
const registries = new Map();
for (const path of registryFiles) {
  const loaded = await loadCanonical(path);
  const document = loaded.value;
  if (document.schemaVersion !== 'ogvcs.authorization/registry/v1' || document.version !== 1 || !Array.isArray(document.entries)) fail(`invalid registry envelope: ${path}`);
  if (registries.has(document.registry)) fail(`duplicate registry: ${document.registry}`);
  const identityField = REGISTRY_IDENTITY_FIELDS[document.registry];
  if (!identityField) fail(`unknown registry identity field: ${document.registry}`);
  const identities = document.entries.map((entry) => entry[identityField]);
  if (identities.some((identity) => typeof identity !== 'string' || identity.length === 0)) {
    fail(`${document.registry} has an invalid ${identityField}`);
  }
  unique(identities, `${document.registry} ${identityField} values`);
  const coded = document.entries.filter(({ code }) => Number.isInteger(code));
  unique(coded.map(({ code }) => code), `${document.registry} codes`);
  const assignmentDigest = sha256(Buffer.from(JSON.stringify(document.entries.map((entry) => ({
    identity: entry[identityField],
    code: Number.isInteger(entry.code) ? entry.code : null,
  })))));
  if (assignmentDigest !== EXPECTED_ASSIGNMENT_SHA256[document.registry]) fail(`registry assignment drift: ${document.registry}`);
  if (sha256(loaded.text) !== EXPECTED_REGISTRY_DOCUMENT_SHA256[document.registry]) fail(`registry document drift: ${document.registry}`);
  registries.set(document.registry, document);
}
exactSet(new Set(registries.keys()), EXPECTED_REGISTRIES, 'registry inventory');
exactSet(new Set(Object.keys(EXPECTED_ASSIGNMENT_SHA256)), EXPECTED_REGISTRIES, 'registry assignment authorities');
exactSet(new Set(Object.keys(EXPECTED_REGISTRY_DOCUMENT_SHA256)), EXPECTED_REGISTRIES, 'registry document authorities');
const recomputedRegistrySet = sha256(Buffer.concat(await Promise.all(registryFiles.map(async (path) => {
  const filename = path.slice('registries/'.length);
  return Buffer.concat([Buffer.from(filename), Buffer.from([0]), Buffer.from((await loadCanonical(path)).text)]);
}))));
if (recomputedRegistrySet !== manifest.registrySetSha256) fail('registry-set digest mismatch');

const permissionEntries = registries.get('permissions').entries;
exactSet(new Set(permissionEntries.map(({ name }) => name)), REQUIRED_PERMISSIONS, 'permission vocabulary');
const permissionIndex = new Map(permissionEntries.map((item) => [item.name, item]));
for (const name of PRIVILEGED_PERMISSIONS) {
  const item = permissionIndex.get(name);
  if (!item?.privileged || !item?.reasonRequired) fail(`privileged permission is not reason-bearing: ${name}`);
}
const resourceNames = new Set(registries.get('resources').entries.map(({ name }) => name));
const decisionIndex = new Map(registries.get('decision-codes').entries.map((item) => [item.name, item]));
const decisionSchemaCases = schemas.get('AuthorizationDecision.schema.json').allOf?.[0]?.oneOf;
const decisionSchemaPolarity = decisionSchemaCases?.map(({ properties }) => ({
  allowed: properties?.allowed?.const,
  codes: properties?.code?.enum,
}));
const expectedDecisionPolarity = [
  { allowed: true, codes: [...decisionIndex.values()].filter(({ allowed }) => allowed).map(({ name }) => name) },
  { allowed: false, codes: [...decisionIndex.values()].filter(({ allowed }) => !allowed).map(({ name }) => name) },
];
if (canonicalJson(decisionSchemaPolarity) !== canonicalJson(expectedDecisionPolarity)) fail('decision allowed/code schema binding is invalid');
if (canonicalJson(schemas.get('AuditEvent.schema.json').properties.outcomeCode.enum) !== canonicalJson([...decisionIndex.keys()])) {
  fail('audit outcome code registry binding is invalid');
}
const auditSchemaEntries = registries.get('audit-classes').entries;
const auditSchemaPairs = schemas.get('AuditEvent.schema.json').allOf?.[0]?.oneOf?.map(({ properties }) => ({
  name: properties?.eventClass?.const,
  permission: properties?.permission?.const,
}));
if (canonicalJson(auditSchemaPairs) !== canonicalJson(auditSchemaEntries.map(({ name, permission }) => ({ name, permission })))) {
  fail('audit class/permission schema binding is invalid');
}
if ([...decisionIndex.values()].some(({ publicSafe }) => publicSafe !== true)) fail('decision code is not privacy-safe');

const threatsRegistry = registries.get('threats').entries;
const coveredActors = new Set(threatsRegistry.flatMap(({ actors }) => actors));
for (const actor of REQUIRED_THREAT_ACTORS) if (!coveredActors.has(actor)) fail(`threat actor missing: ${actor}`);
for (const threat of threatsRegistry) {
  if (['critical', 'high'].includes(threat.severity) && threat.status !== 'mitigated') fail(`unresolved ${threat.severity} threat: ${threat.name}`);
  if (threat.severity === 'medium' && threat.status === 'accepted' && (!threat.owner || !threat.roadmapItem || !threat.expiry)) fail(`accepted medium threat has no owner/roadmap/expiry: ${threat.name}`);
  if (!Array.isArray(threat.mitigations) || threat.mitigations.length === 0 || !Array.isArray(threat.abuseCases) || threat.abuseCases.length === 0) fail(`threat has no executable mitigation: ${threat.name}`);
}
const abuseEntries = registries.get('abuse-cases').entries;
const abuseNames = new Set(abuseEntries.map(({ name }) => name));
const abuseCategories = new Set(abuseEntries.map(({ category }) => category));
for (const category of REQUIRED_ABUSE_CATEGORIES) if (!abuseCategories.has(category)) fail(`required abuse category missing: ${category}`);
for (const threat of threatsRegistry) for (const abuseCase of threat.abuseCases) if (!abuseNames.has(abuseCase)) fail(`threat references unknown abuse case: ${abuseCase}`);

const revocations = new Map(registries.get('revocation-classes').entries.map((item) => [item.name, item]));
for (const name of ['session', 'service-token', 'transfer-grant', 'authorization-cache', 'offline-lock-receipt']) {
  const item = revocations.get(name);
  if (!item || item.epochBound !== true || item.maximumValiditySeconds <= 0 || item.maximumRevocationLagSeconds <= 0 || item.maximumRevocationLagSeconds > item.maximumValiditySeconds) fail(`invalid revocation class: ${name}`);
}
if (revocations.get('transfer-grant').maximumValiditySeconds !== 300 || revocations.get('authorization-cache').maximumValiditySeconds > 30) fail('grant/cache validity ceiling drift');

const sandboxes = registries.get('sandbox-profiles').entries;
exactSet(new Set(sandboxes.map(({ toolClass }) => toolClass)), new Set(['hook', 'merge-driver', 'import-parser', 'preview-parser']), 'sandbox tool classes');
for (const profile of sandboxes) {
  if (profile.network.default !== 'deny' || profile.credentials !== 'none' || profile.filesystem.declaredInputsReadOnly !== true || profile.filesystem.isolatedScratch !== true || profile.filesystem.hostPaths !== false || profile.toolchain.pinned !== true || profile.toolchain.signatureRequired !== true) fail(`unsafe sandbox profile: ${profile.id}`);
  if (Object.values(profile.runtime).some((value) => !Number.isSafeInteger(value) || value <= 0)) fail(`invalid sandbox resource ceiling: ${profile.id}`);
}

const auditEntries = registries.get('audit-classes').entries;
const auditedPermissions = new Set(auditEntries.map(({ permission }) => permission));
for (const permission of PRIVILEGED_PERMISSIONS) if (!auditedPermissions.has(permission)) fail(`privileged permission has no audit class: ${permission}`);
if (auditEntries.some(({ reasonRequired, redaction }) => reasonRequired !== true || typeof redaction !== 'string')) fail('audit class lacks reason/redaction');

const roadmapText = await readFile(resolve(REPOSITORY_ROOT, 'prd/ROADMAP.md'), 'utf8');
const roadmapPrds = new Set(roadmapText.match(/OGVCS-[0-9]{3}/g));
if (roadmapPrds.size !== EXPECTED.roadmapPrds) fail('unexpected roadmap PRD cardinality');
const surfaceEntries = registries.get('roadmap-surfaces').entries;
exactSet(new Set(surfaceEntries.map(({ prd }) => prd)), roadmapPrds, 'roadmap surface coverage');
for (const surface of surfaceEntries) {
  if (!['public-contract', 'protected', 'mixed'].includes(surface.classification) || !['public-no-audit', 'authorization-decision', 'privileged-append-only'].includes(surface.auditBehavior) || !Array.isArray(surface.surfaces) || surface.surfaces.length === 0) fail(`invalid roadmap surface: ${surface.prd}`);
  if (surface.classification === 'public-contract' && (surface.resourceTypes.length !== 0 || surface.permissions.length !== 0)) fail(`public surface carries protected permission: ${surface.prd}`);
  if (surface.classification === 'public-contract' && surface.auditBehavior !== 'public-no-audit') fail(`public surface has protected audit behavior: ${surface.prd}`);
  if (surface.classification !== 'public-contract' && surface.auditBehavior === 'public-no-audit') fail(`protected surface lacks audit behavior: ${surface.prd}`);
  if (surface.permissions.some((permission) => PRIVILEGED_PERMISSIONS.has(permission)) && surface.auditBehavior !== 'privileged-append-only') fail(`privileged surface lacks append-only audit: ${surface.prd}`);
  for (const permission of surface.permissions) if (!permissionIndex.has(permission)) fail(`roadmap surface uses unknown permission: ${surface.prd}/${permission}`);
  for (const resource of surface.resourceTypes) if (!resourceNames.has(resource)) fail(`roadmap surface uses unknown resource: ${surface.prd}/${resource}`);
}

const policyFiles = await listedJson('policies');
exactSet(new Set(policyFiles.map((path) => path.slice('policies/'.length))), new Set(['internal-team.json', 'restricted-outsourcer.json']), 'policy fixtures');
const policyIndex = new Map();
for (const path of policyFiles) {
  const policy = (await loadCanonical(path)).value;
  if (policy.schemaVersion !== 'ogvcs.authorization/policy-fixture/v1' || policy.default !== 'deny' || policy.composition !== 'deny-overrides-v1' || !Array.isArray(policy.rules) || policy.rules.length === 0) fail(`invalid policy fixture: ${path}`);
  if (!/^[a-z][a-z0-9.-]{0,127}$/.test(`${policy.id}.${policy.version}`)) fail(`invalid combined policy version: ${path}`);
  unique(policy.rules.map(({ id }) => id), `${path} rule IDs`);
  for (const rule of policy.rules) {
    if (!['allow', 'deny'].includes(rule.effect)) fail(`invalid policy effect: ${path}/${rule.id}`);
    for (const permission of rule.permissions) if (!permissionIndex.has(permission)) fail(`unknown policy permission: ${path}/${permission}`);
    for (const resource of rule.resourceTypes) if (!resourceNames.has(resource)) fail(`unknown policy resource: ${path}/${resource}`);
  }
  policyIndex.set(path.slice('policies/'.length), policy);
}

const decisions = (await loadCanonical('vectors/decisions.json')).value;
if (decisions.schemaVersion !== 'ogvcs.authorization/decision-vectors/v1' || decisions.cases.length !== EXPECTED.decisionVectors) fail('decision vector envelope mismatch');
unique(decisions.cases.map(({ id }) => id), 'decision vector IDs');
for (const policyName of policyIndex.keys()) {
  const covered = new Set(decisions.cases.filter(({ policy }) => policy === policyName).map(({ request }) => request.permission));
  exactSet(covered, REQUIRED_PERMISSIONS, `${policyName} permission decisions`);
}
for (const testCase of decisions.cases) {
  const policy = policyIndex.get(testCase.policy);
  if (!policy) fail(`decision vector uses unknown policy: ${testCase.id}`);
  const actual = independentDecision(policy, testCase.request, permissionIndex);
  if (testCase.expected.allowed !== actual.allowed || testCase.expected.code !== actual.code || testCase.expected.decisionFingerprint !== actual.fingerprint) fail(`decision vector mismatch: ${testCase.id}`);
  const keys = new Set(Object.keys(testCase.expected));
  for (const forbidden of REQUIRED_FORBIDDEN_FIELDS) if (keys.has(forbidden)) fail(`decision leaks ${forbidden}: ${testCase.id}`);
}
const denyWins = decisions.cases.find(({ id }) => id === 'deny-overrides-overlapping-allow');
const denyWinsPolicy = denyWins && policyIndex.get(denyWins.policy);
const denyWinsMatches = denyWinsPolicy ? denyWinsPolicy.rules.filter((rule) => matches(rule, denyWins.request)).map(({ effect }) => effect) : [];
if (denyWins?.expected.code !== 'DENY_NOT_AUTHORIZED' || !denyWinsMatches.includes('allow') || !denyWinsMatches.includes('deny')) fail('deny-overrides witness missing');

const grants = (await loadCanonical('vectors/grants.json')).value;
if (grants.schemaVersion !== 'ogvcs.authorization/grant-vectors/v1' || grants.conformanceOnly !== true || grants.cases.length !== EXPECTED.grantVectors) fail('grant vector envelope mismatch');
for (const testCase of grants.cases) {
  const contextKeys = new Set(Object.keys(testCase.context));
  exactSet(contextKeys, new Set(['schemaVersion', 'issuer', 'keyId', 'subject', 'permission', 'operation', 'audience', 'tenant', 'repository', 'authorityEpoch', 'keyGeneration', 'now', 'objectId', 'requestObjectIds', 'consumedNonces']), `grant context fields: ${testCase.id}`);
  if (testCase.context.schemaVersion !== 'ogvcs.authorization/transfer-grant-context/v1' || !Array.isArray(testCase.context.requestObjectIds) || testCase.context.requestObjectIds.length > 32_768 || new Set(testCase.context.requestObjectIds).size !== testCase.context.requestObjectIds.length) fail(`grant context shape mismatch: ${testCase.id}`);
  const actualCode = independentGrantResult(testCase, grants.key.publicJwk);
  if (actualCode !== testCase.expected.code || (actualCode.startsWith('ALLOW_') ? 'allow' : 'deny') !== testCase.expected.result) fail(`grant vector mismatch: ${testCase.id}`);
  const claims = testCase.envelope.claims;
  if (claims.expiresAt - claims.issuedAt > revocations.get('transfer-grant').maximumValiditySeconds) fail(`grant exceeds TTL: ${testCase.id}`);
}

const abuseVectors = (await loadCanonical('vectors/abuse-catalog.json')).value;
if (abuseVectors.schemaVersion !== 'ogvcs.authorization/abuse-vectors/v1' || abuseVectors.cases.length !== EXPECTED.abuseVectors) fail('abuse vector envelope mismatch');
exactSet(new Set(abuseVectors.cases.map(({ abuseCase }) => abuseCase)), abuseNames, 'abuse vector coverage');
for (const vector of abuseVectors.cases) {
  if (!decisionIndex.has(vector.expected.code)) fail(`abuse vector has unknown decision: ${vector.id}`);
  exactSet(new Set(vector.forbiddenResponseFields), REQUIRED_FORBIDDEN_FIELDS, `forbidden response fields: ${vector.id}`);
}

const view = (await loadCanonical('vectors/authorized-views.json')).value;
const viewPolicy = policyIndex.get(view.policy);
const repository = (await loadCanonical('vectors/golden-repository.json')).value;
const actor = repository.actors.find(({ id }) => id === view.actor);
const visible = [];
for (const item of view.input) {
  const resource = structuredClone(item);
  delete resource.id;
  delete resource.visibility;
  const request = {
    schemaVersion: 'ogvcs.authorization/request/v1', requestId: `view-${item.id}`, actor,
    tenant: repository.tenant, repository: repository.repository, permission: view.permission,
    reason: null, resource,
    context: { reference: 'main', snapshot: 'snapshot-main-0001', policyGeneration: repository.policyGeneration, authorityEpoch: repository.authorityEpoch },
  };
  if (independentDecision(viewPolicy, request, permissionIndex).allowed) visible.push(item.id);
}
if (canonicalJson(visible) !== canonicalJson(view.expectedVisibleIds)) fail('authorized-view fixture mismatch');
if (!view.forbiddenAggregateFields.includes('hiddenCount') || !view.forbiddenAggregateFields.includes('globalCursor')) fail('authorized-view does not forbid global aggregates');

const vectorManifest = (await loadCanonical('vectors/manifest.json')).value;
if (vectorManifest.registrySetSha256 !== manifest.registrySetSha256 || vectorManifest.contractVersion !== manifest.contractVersion) fail('vector manifest authority mismatch');
for (const vector of vectorManifest.vectors) {
  const loaded = await loadCanonical(vector.path);
  if (sha256(loaded.text) !== vector.sha256) fail(`vector digest mismatch: ${vector.path}`);
}

const requiredDocs = ['README.md', 'LICENSE', 'docs/threat-model.md', 'docs/privacy-review.md', 'docs/versioning.md', 'docs/runner-protocol.md', 'docs/sandbox-contract.md', 'docs/operations.md'];
for (const path of requiredDocs) {
  try {
    const metadata = await lstat(resolve(ROOT, path));
    if (!metadata.isFile() || metadata.isSymbolicLink()) fail(`required document is unsafe: ${path}`);
  } catch (error) {
    if (error.message?.startsWith('authorization-contract-v1:')) throw error;
    fail(`required document missing: ${path}`);
  }
}
const license = await readFile(resolve(ROOT, 'LICENSE'), 'utf8');
const repositoryLicense = await readFile(resolve(REPOSITORY_ROOT, 'LICENSE'), 'utf8');
if (license !== repositoryLicense) fail('MIT license text differs from repository authority');

process.stdout.write(`${JSON.stringify({
  schema: 'ogvcs.authorization.validation-result/v1',
  contractVersion: manifest.contractVersion,
  registrySetSha256: manifest.registrySetSha256,
  schemas: manifest.schemas,
  registries: manifest.registries,
  policies: manifest.policies,
  decisionVectors: manifest.decisionVectors,
  abuseVectors: manifest.abuseVectors,
  grantVectors: manifest.grantVectors,
  roadmapPrds: roadmapPrds.size,
  result: 'valid',
})}\n`);
