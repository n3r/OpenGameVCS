#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const workspace = resolve(root, '../../..');
const migrations = resolve(root, '../../migrations/repository-metadata');
const identityMigrations = resolve(root, '../../migrations/identity-policy-audit');
const lifecycleContractRoot = resolve(root, 'contracts/lifecycle-bridge/v1');

function assert(condition, message) { if (!condition) throw new Error(message); }
function digest(bytes) { return createHash('sha256').update(bytes).digest('hex'); }
function decodeExactHex(value, byteLength, label) {
  assert(
    typeof value === 'string'
      && new RegExp(`^[0-9a-f]{${byteLength * 2}}$`, 'u').test(value),
    `${label} is not exact lowercase hexadecimal`,
  );
  return Buffer.from(value, 'hex');
}
function decodeExactUuid(value, label) {
  assert(
    typeof value === 'string'
      && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u.test(value),
    `${label} is not a canonical lowercase UUID`,
  );
  return Buffer.from(value.replaceAll('-', ''), 'hex');
}
function encodeUnsigned(value, width, label) {
  let integer;
  try { integer = BigInt(value); } catch { throw new Error(`${label} is not an unsigned integer`); }
  assert(integer >= 0n && integer < (1n << BigInt(width * 8)), `${label} exceeds u${width * 8}`);
  const encoded = Buffer.alloc(width);
  for (let offset = width - 1; offset >= 0; offset -= 1) {
    encoded[offset] = Number(integer & 0xffn);
    integer >>= 8n;
  }
  return encoded;
}
function requiredFrame(value) {
  return Buffer.concat([encodeUnsigned(value.length, 8, 'field byte length'), value]);
}
function vectorFieldValue(input, descriptor) {
  const value = input[descriptor.binding];
  if (descriptor.component === 'unix-seconds') return value?.unixSeconds;
  if (descriptor.component === 'nanoseconds') return value?.nanoseconds;
  return value;
}
function encodedVectorValue(input, descriptor) {
  const label = descriptor.component
    ? `${descriptor.binding}.${descriptor.component}`
    : descriptor.binding;
  const value = vectorFieldValue(input, descriptor);
  switch (descriptor.type) {
    case 'utf8':
      assert(typeof value === 'string', `${label} is not a string`);
      return Buffer.from(value, 'utf8');
    case 'optional-utf8':
      assert(value === null || typeof value === 'string', `${label} is not an optional string`);
      return value === null
        ? Buffer.from([0])
        : Buffer.concat([Buffer.from([1]), requiredFrame(Buffer.from(value, 'utf8'))]);
    case 'sha256-raw': return decodeExactHex(value, 32, label);
    case 'sha256-hex-utf8':
      decodeExactHex(value, 32, label);
      return Buffer.from(value, 'utf8');
    case 'uuid-raw': return decodeExactUuid(value, label);
    case 'u64-be': return encodeUnsigned(value, 8, label);
    case 'u32-be': return encodeUnsigned(value, 4, label);
    case 'u16-be': return encodeUnsigned(value, 2, label);
    default: throw new Error(`unknown lifecycle operation field type: ${descriptor.type}`);
  }
}
function operationDigest(contract, input) {
  const fields = contract.operationDigest.orderedFields.map((descriptor) => {
    const encoded = encodedVectorValue(input, descriptor);
    return descriptor.type === 'optional-utf8' ? encoded : requiredFrame(encoded);
  });
  const domain = Buffer.from(contract.operationDigest.domainUtf8, 'utf8');
  return digest(Buffer.concat([domain, Buffer.from([0]), ...fields]));
}

const cargo = await readFile(resolve(root, 'Cargo.toml'), 'utf8');
assert(cargo.includes('name = "ogvcs-repository-metadata"'), 'Cargo package name differs');
assert(cargo.includes('ogvcs-object-model = { path = "../../../core/object-model/rust" }'), 'object-model dependency is not public path dependency');
assert(cargo.includes('postgres = { version = "=0.19.10"'), 'PostgreSQL dependency is not exactly pinned');
assert(cargo.includes('unicode-normalization = "=0.1.24"'), 'NFC dependency is not exactly pinned');
assert(cargo.includes('rust-version = "1.82"'), 'Rust MSRV differs');
assert(cargo.includes('legacy-test-adapter = []'), 'legacy adapter is not feature-gated');
assert(cargo.includes('required-features = ["legacy-test-adapter"]'), 'legacy live test is not isolated behind its feature');

const rustFiles = [
  'lib.rs',
  'error.rs',
  'migration.rs',
  'migration_runner.rs',
  'lifecycle.rs',
  'ports.rs',
  'postgres.rs',
  'service.rs',
  'postgres/aggregate_bridge.rs',
  'postgres/atomic_submit.rs',
  'postgres/metadata_dispatcher.rs',
  'types.rs',
];
for (const file of rustFiles) {
  const source = await readFile(resolve(root, 'src', file), 'utf8');
  assert(!/\bunsafe\b/u.test(source.replace('#![forbid(unsafe_code)]', '')), `unsafe Rust appears in ${file}`);
}

const manifest = JSON.parse(await readFile(resolve(migrations, 'manifest.json')));
assert(manifest.schemaVersion === 'ogvcs.repository-metadata/migration-manifest/v1', 'migration manifest schema differs');
assert(JSON.stringify(manifest.entries.map(({ version, phase }) => [version, phase])) === '[[1,"expand"],[1,"migrate"],[1,"contract"],[2,"expand"],[2,"migrate"],[2,"contract"],[3,"expand"],[3,"migrate"],[3,"contract"],[4,"expand"],[4,"migrate"],[4,"contract"],[5,"expand"],[5,"migrate"],[5,"contract"],[6,"expand"],[6,"migrate"],[6,"contract"],[7,"expand"],[7,"migrate"],[7,"contract"],[8,"expand"],[8,"migrate"],[8,"contract"],[9,"expand"],[9,"migrate"],[9,"contract"],[10,"expand"],[10,"migrate"],[10,"contract"],[11,"expand"],[11,"migrate"],[11,"contract"]]', 'migration phases are not ordered');
for (const entry of manifest.entries) {
  const bytes = await readFile(resolve(migrations, entry.path));
  const sql = bytes.toString('utf8');
  assert(digest(bytes) === entry.sha256, `migration checksum differs: ${entry.path}`);
  assert(sql.startsWith('BEGIN;\n') && sql.endsWith('COMMIT;\n'), `migration is not transaction framed: ${entry.path}`);
}

const lifecycleManifestBytes = await readFile(resolve(lifecycleContractRoot, 'manifest.json'));
const lifecycleManifest = JSON.parse(lifecycleManifestBytes);
const lifecycleSource = await readFile(resolve(root, 'src/lifecycle.rs'), 'utf8');
assert(
  lifecycleManifest.schemaVersion === 'ogvcs.repository-metadata/lifecycle-authorization-bridge-manifest/v1',
  'lifecycle bridge manifest schema differs',
);
assert(lifecycleManifest.contractVersion === '0.1.0-rc.6', 'lifecycle bridge version differs');
assert(
  lifecycleSource.includes(`"${digest(lifecycleManifestBytes)}"`),
  'Rust lifecycle contract manifest digest is stale',
);
const expectedLifecycleArtifactPaths = [
  'contract.json',
  'vectors/operation-digest.json',
];
assert(
  JSON.stringify(lifecycleManifest.artifacts.map(({ path }) => path))
    === JSON.stringify(expectedLifecycleArtifactPaths),
  'lifecycle bridge artifact inventory differs',
);
const lifecycleArtifacts = [];
for (const artifact of lifecycleManifest.artifacts) {
  const artifactBytes = await readFile(resolve(lifecycleContractRoot, artifact.path));
  assert(artifactBytes.length === artifact.bytes, `lifecycle artifact size differs: ${artifact.path}`);
  assert(digest(artifactBytes) === artifact.sha256, `lifecycle artifact digest differs: ${artifact.path}`);
  lifecycleArtifacts.push(Buffer.from(`${artifact.path}\0${artifact.sha256}\0${artifact.bytes}\n`));
}
const lifecycleArtifactSet = digest(Buffer.concat(lifecycleArtifacts));
assert(
  lifecycleArtifactSet === lifecycleManifest.artifactSetSha256,
  'lifecycle bridge artifact-set digest differs',
);
assert(
  lifecycleSource.includes(`"${lifecycleArtifactSet}"`),
  'Rust lifecycle artifact-set digest is stale',
);
const lifecycleContract = JSON.parse(
  await readFile(resolve(lifecycleContractRoot, 'contract.json'), 'utf8'),
);
assert(
  lifecycleContract.contractVersion === lifecycleManifest.contractVersion,
  'lifecycle artifact/manifest versions differ',
);
assert(lifecycleContract.publicClaims.ogvcs009Complete === false, 'OGVCS-009 completion is claimed');
assert(
  lifecycleContract.publicClaims.ogvcs010DisasterRecoveryReceipt === false,
  'OGVCS-010 disaster-recovery receipt is claimed',
);
assert(
  lifecycleContract.publicClaims.trustedRootProofAuthorityExternal === false,
  'trusted external root-proof authority is claimed',
);
assert(
  lifecycleContract.dependencies.objectTransferManifestSha256
    === lifecycleSource.match(/pub const OBJECT_TRANSFER_MANIFEST_SHA256: &str =\s*\n?\s*"([0-9a-f]{64})"/u)?.[1],
  'lifecycle artifact object-transfer manifest pin differs from Rust',
);
assert(
  lifecycleContract.dependencies.objectTransferArtifactSetSha256
    === lifecycleSource.match(/pub const OBJECT_TRANSFER_ARTIFACT_SET_SHA256: &str =\s*\n?\s*"([0-9a-f]{64})"/u)?.[1],
  'lifecycle artifact object-transfer artifact-set pin differs from Rust',
);
const identityPolicyManifestBytes = await readFile(
  resolve(workspace, 'spec/identity-policy-audit/v1/manifest.json'),
);
const identityPolicyManifest = JSON.parse(identityPolicyManifestBytes);
assert(
  digest(identityPolicyManifestBytes) === lifecycleContract.dependencies.identityPolicyManifestSha256,
  'lifecycle artifact identity-policy manifest pin differs',
);
assert(
  identityPolicyManifest.artifactSetSha256
    === lifecycleContract.dependencies.identityPolicyArtifactSetSha256,
  'lifecycle artifact identity-policy artifact-set pin differs',
);
const authorizationManifestBytes = await readFile(
  resolve(workspace, 'spec/authorization/v1/manifest.json'),
);
assert(
  digest(authorizationManifestBytes)
    === lifecycleContract.dependencies.authorizationManifestSha256,
  'lifecycle artifact authorization manifest pin differs',
);
assert(
  lifecycleSource.includes(
    `pub const AUTHORIZATION_MANIFEST_SHA256: &str =\n    "${lifecycleContract.dependencies.authorizationManifestSha256}";`,
  ),
  'Rust authorization manifest pin differs from lifecycle artifact',
);
const identityMigrationManifestBytes = await readFile(resolve(identityMigrations, 'manifest.json'));
const identityMigrationManifest = JSON.parse(identityMigrationManifestBytes);
assert(
  digest(identityMigrationManifestBytes)
    === lifecycleContract.dependencies.identityMigrationManifestSha256,
  'lifecycle artifact identity migration manifest pin differs',
);
assert(
  identityMigrationManifest.schemaVersion
    === 'ogvcs.identity-policy/postgres-migration-manifest/v1',
  'identity migration manifest schema differs',
);
assert(lifecycleContract.dependencies.identityMigration === 3, 'identity migration version differs');
const identityMigrationV3 = identityMigrationManifest.entries.filter(({ version }) => version === 3);
assert(
  JSON.stringify(identityMigrationV3.map(({ phase, sha256 }) => [phase, sha256]))
    === JSON.stringify([
      ['expand', lifecycleContract.dependencies.identityMigrationV3.expandSha256],
      ['migrate', lifecycleContract.dependencies.identityMigrationV3.migrateSha256],
      ['contract', lifecycleContract.dependencies.identityMigrationV3.contractSha256],
    ]),
  'identity migration v3 phase pins differ',
);
for (const phase of identityMigrationV3) {
  assert(
    digest(await readFile(resolve(identityMigrations, phase.path))) === phase.sha256,
    `identity migration v3 SQL differs: ${phase.path}`,
  );
}
const identityAggregateSource = await readFile(
  resolve(root, '../identity-policy-audit/src/aggregate.rs'),
  'utf8',
);
assert(
  identityAggregateSource.includes(
    `pub const AGGREGATE_AUTHORIZATION_RECEIPT_SCHEMA: &str =\n    "${lifecycleContract.dependencies.aggregateAuthorizationReceipt}";`,
  ),
  'identity aggregate receipt schema dependency differs',
);
const expectedOperationDigestSemantics = {
  algorithm: 'sha-256',
  domainUtf8: 'OGVCS-LIFECYCLE-AUTHORIZED-OPERATION-V1',
  domainHex: '4f475643532d4c4946454359434c452d415554484f52495a45442d4f5045524154494f4e2d5631',
  formula: 'SHA-256(domain-utf8 || 0x00 || ordered-framed-fields)',
  requiredFieldFraming: 'u64-be(value-byte-length) || value-bytes',
  optionalFieldFraming: '0x00 when absent; 0x01 || u64-be(value-byte-length) || value-bytes when present',
  stringEncoding: 'utf-8 exact validated bytes',
  digestEncoding: 'raw 32 bytes unless type is sha256-hex-utf8',
  uuidEncoding: 'raw RFC-4122 network-order 16 bytes',
  integerEncoding: 'unsigned fixed-width big-endian',
  timestampEncoding: 'Unix seconds as u64-be followed by nanoseconds as u32-be',
};
for (const [field, value] of Object.entries(expectedOperationDigestSemantics)) {
  assert(lifecycleContract.operationDigest[field] === value, `operation digest ${field} differs`);
}
const expectedOperationTypeEncodings = {
  utf8: 'the exact UTF-8 bytes of the JSON string',
  'optional-utf8': 'the optional-field tag followed, when present, by the required framing of the exact UTF-8 bytes',
  'sha256-raw': "exactly 32 bytes decoded from the JSON value's 64 lowercase hexadecimal characters",
  'sha256-hex-utf8': 'the exact 64 lowercase ASCII hexadecimal characters encoded as UTF-8; do not hex-decode',
  'uuid-raw': 'exactly 16 RFC-4122 network-order bytes decoded from the canonical lowercase hyphenated UUID',
  'u64-be': 'exactly 8 bytes containing the unsigned integer in big-endian order',
  'u32-be': 'exactly 4 bytes containing the unsigned integer in big-endian order',
  'u16-be': 'exactly 2 bytes containing the unsigned integer in big-endian order',
};
assert(
  JSON.stringify(lifecycleContract.operationDigest.typeEncodings)
    === JSON.stringify(expectedOperationTypeEncodings),
  'operation digest type encodings differ',
);
assert(
  Buffer.from(lifecycleContract.operationDigest.domainUtf8, 'utf8').toString('hex')
    === lifecycleContract.operationDigest.domainHex,
  'operation digest domain UTF-8 and raw bytes differ',
);
const operationVector = JSON.parse(
  await readFile(resolve(lifecycleContractRoot, 'vectors/operation-digest.json'), 'utf8'),
);
assert(
  operationVector.schemaVersion
    === 'ogvcs.repository-metadata/lifecycle-authorization-bridge-operation-vector/v1',
  'operation digest vector schema differs',
);
const recomputedOperationDigest = operationDigest(lifecycleContract, operationVector.input);
assert(
  recomputedOperationDigest === operationVector.expectedOperationDigestSha256,
  'operation digest golden vector differs',
);
const tamperedOperationInput = structuredClone(operationVector.input);
tamperedOperationInput['consumption-id'] = `${tamperedOperationInput['consumption-id']}.tampered`;
assert(
  operationDigest(lifecycleContract, tamperedOperationInput)
    !== operationVector.expectedOperationDigestSha256,
  'operation digest vector does not detect tampering',
);
const aggregateBridge = await readFile(resolve(root, 'src/postgres/aggregate_bridge.rs'), 'utf8');
const requiredBridgeBindings = [
  'identity-receipt-schema-version',
  'identity-plan-id',
  'identity-decision-digest',
  'lifecycle-plan-id',
  'lifecycle-plan-digest',
  'identity-plan-nonce',
  'identity-tenant-id',
  'identity-repository-id',
  'metadata-tenant-id',
  'metadata-repository-id',
  'subject-digest',
  'authenticated-scope-digest',
  'credential-generation',
  'authority-epoch',
  'security-epoch',
  'policy-generation',
  'policy-digest',
  'settings-generation',
  'settings-descriptor-digest',
  'path-profile',
  'case-mode',
  'permission',
  'capability',
  'reference',
  'snapshot',
  'publication-object-kind',
  'publication-object-digest',
  'candidate-digest',
  'authority-contract-digest',
  'reason-digest',
  'identity-resource-count',
  'resource-set-digest',
  'resource-digest-projection-digest',
  'lifecycle-object-count',
  'lifecycle-chunk-count',
  'lifecycle-encoded-bytes',
  'lifecycle-expiry',
  'object-transfer-manifest-digest',
  'object-transfer-artifact-set-digest',
  'lifecycle-contract-manifest-digest',
  'lifecycle-contract-artifact-set-digest',
  'idempotency-operation',
  'idempotency-key',
  'idempotency-scope-digest',
  'semantic-fingerprint',
  'identity-issued-at',
  'identity-expires-at',
  'signer-key-generation',
  'signer-key-reference',
  'signer-key-fingerprint',
  'consumption-id',
  'operation-digest',
];
assert(
  new Set(requiredBridgeBindings).size === requiredBridgeBindings.length,
  'static required-binding registry contains a duplicate',
);
assert(
  new Set(lifecycleContract.requiredBindings).size === lifecycleContract.requiredBindings.length,
  'lifecycle contract required-binding registry contains a duplicate',
);
const expectedOrderedBridgeFields = [
  ['identity-receipt-schema-version', 'utf8'],
  ['identity-plan-id', 'utf8'],
  ['identity-decision-digest', 'sha256-raw'],
  ['identity-tenant-id', 'utf8'],
  ['identity-repository-id', 'utf8'],
  ['metadata-tenant-id', 'uuid-raw'],
  ['metadata-repository-id', 'uuid-raw'],
  ['lifecycle-plan-id', 'uuid-raw'],
  ['lifecycle-plan-digest', 'sha256-raw'],
  ['identity-resource-count', 'u64-be'],
  ['lifecycle-object-count', 'u64-be'],
  ['lifecycle-chunk-count', 'u64-be'],
  ['lifecycle-encoded-bytes', 'u64-be'],
  ['lifecycle-expiry', 'u64-be', 'unix-seconds'],
  ['lifecycle-expiry', 'u32-be', 'nanoseconds'],
  ['publication-object-kind', 'u16-be'],
  ['publication-object-digest', 'sha256-raw'],
  ['candidate-digest', 'sha256-raw'],
  ['authority-contract-digest', 'sha256-raw'],
  ['object-transfer-manifest-digest', 'sha256-hex-utf8'],
  ['object-transfer-artifact-set-digest', 'sha256-hex-utf8'],
  ['lifecycle-contract-manifest-digest', 'sha256-hex-utf8'],
  ['lifecycle-contract-artifact-set-digest', 'sha256-hex-utf8'],
  ['subject-digest', 'sha256-raw'],
  ['authenticated-scope-digest', 'sha256-raw'],
  ['credential-generation', 'u64-be'],
  ['authority-epoch', 'u64-be'],
  ['security-epoch', 'u64-be'],
  ['policy-generation', 'u64-be'],
  ['policy-digest', 'sha256-raw'],
  ['settings-generation', 'u64-be'],
  ['settings-descriptor-digest', 'sha256-raw'],
  ['path-profile', 'utf8'],
  ['case-mode', 'utf8'],
  ['permission', 'utf8'],
  ['capability', 'utf8'],
  ['reference', 'optional-utf8'],
  ['snapshot', 'optional-utf8'],
  ['reason-digest', 'sha256-raw'],
  ['resource-set-digest', 'sha256-raw'],
  ['resource-digest-projection-digest', 'sha256-raw'],
  ['identity-plan-nonce', 'sha256-raw'],
  ['idempotency-operation', 'utf8'],
  ['idempotency-key', 'utf8'],
  ['idempotency-scope-digest', 'sha256-raw'],
  ['semantic-fingerprint', 'sha256-raw'],
  ['consumption-id', 'utf8'],
  ['identity-issued-at', 'u64-be'],
  ['identity-expires-at', 'u64-be'],
  ['signer-key-generation', 'u64-be'],
  ['signer-key-reference', 'utf8'],
  ['signer-key-fingerprint', 'sha256-raw'],
];
const actualOrderedBridgeFields = lifecycleContract.operationDigest.orderedFields.map(
  ({ binding, type, component }) => component ? [binding, type, component] : [binding, type],
);
assert(
  JSON.stringify(actualOrderedBridgeFields) === JSON.stringify(expectedOrderedBridgeFields),
  'lifecycle bridge ordered typed digest fields differ',
);
const orderedBindingSet = new Set(
  lifecycleContract.operationDigest.orderedFields.map(({ binding }) => binding),
);
assert(
  requiredBridgeBindings.every((binding) => binding === 'operation-digest' || orderedBindingSet.has(binding))
    && [...orderedBindingSet].every((binding) => requiredBridgeBindings.includes(binding)),
  'lifecycle bridge required/ordered binding registries differ',
);
assert(
  JSON.stringify(lifecycleContract.requiredBindings) === JSON.stringify(requiredBridgeBindings),
  'lifecycle bridge required-binding registry differs',
);
const bindingNeedles = {
  'identity-receipt-schema-version': 'AggregateAuthorizationReceipt::schema_version()',
  'identity-plan-id': 'receipt.plan_id().as_bytes()',
  'identity-decision-digest': '&facts.decision_digest',
  'lifecycle-plan-id': 'plan.plan_id.as_bytes()',
  'lifecycle-plan-digest': '&plan.plan_digest',
  'identity-plan-nonce': '&facts.plan_nonce',
  'identity-tenant-id': 'receipt.tenant().as_bytes()',
  'identity-repository-id': 'receipt.repository().as_bytes()',
  'metadata-tenant-id': 'plan.tenant_id.as_bytes()',
  'metadata-repository-id': 'plan.repository_id.as_bytes()',
  'subject-digest': '&facts.subject_digest',
  'authenticated-scope-digest': '&facts.scope_digest',
  'credential-generation': 'receipt.credential_generation()',
  'authority-epoch': 'receipt.authority_epoch()',
  'security-epoch': 'receipt.security_epoch()',
  'policy-generation': 'receipt.policy_generation()',
  'policy-digest': '&facts.policy_digest',
  'settings-generation': 'receipt.settings_generation()',
  'settings-descriptor-digest': '&facts.settings_digest',
  'path-profile': 'receipt.path_profile().as_bytes()',
  'case-mode': 'receipt.case_mode().as_bytes()',
  permission: 'receipt.permission().as_bytes()',
  capability: 'receipt.capability().as_bytes()',
  reference: 'receipt.reference().map(str::as_bytes)',
  snapshot: 'receipt.snapshot().map(str::as_bytes)',
  'publication-object-kind': 'plan.publication.kind.code()',
  'publication-object-digest': '&plan.publication.digest',
  'candidate-digest': '&plan.candidate_digest',
  'authority-contract-digest': '&plan.authority_contract_digest',
  'reason-digest': '&facts.reason_digest',
  'identity-resource-count': 'BridgeOperationField::U64(identity_resource_count)',
  'resource-set-digest': '&facts.resource_set_digest',
  'resource-digest-projection-digest': '&facts.projection_digest',
  'lifecycle-object-count': 'u64::from(plan.object_count)',
  'lifecycle-chunk-count': 'u64::from(plan.chunk_count)',
  'lifecycle-encoded-bytes': 'BridgeOperationField::U64(plan.encoded_bytes)',
  'lifecycle-expiry': 'lifecycle_expiry.subsec_nanos()',
  'object-transfer-manifest-digest': 'OBJECT_TRANSFER_MANIFEST_SHA256.as_bytes()',
  'object-transfer-artifact-set-digest': 'OBJECT_TRANSFER_ARTIFACT_SET_SHA256.as_bytes()',
  'lifecycle-contract-manifest-digest': 'LIFECYCLE_CONTRACT_SHA256.as_bytes()',
  'lifecycle-contract-artifact-set-digest': 'LIFECYCLE_CONTRACT_ARTIFACT_SET_SHA256.as_bytes()',
  'idempotency-operation': 'plan.idempotency_operation.as_bytes()',
  'idempotency-key': 'plan.idempotency_key.as_bytes()',
  'idempotency-scope-digest': '&plan.idempotency_scope_digest',
  'semantic-fingerprint': '&plan.semantic_fingerprint',
  'identity-issued-at': 'receipt.issued_at()',
  'identity-expires-at': 'receipt.expires_at()',
  'signer-key-generation': 'receipt.signer_key_generation()',
  'signer-key-reference': 'receipt.signer_key_reference().as_bytes()',
  'signer-key-fingerprint': '&facts.signer_fingerprint',
  'consumption-id': 'consumption_id.as_bytes()',
  'operation-digest': 'BRIDGE_OPERATION_DOMAIN',
};
const operationDigestStart = aggregateBridge.indexOf('fn bridge_operation_digest(');
const operationDigestEnd = aggregateBridge.indexOf('\nenum BridgeOperationField', operationDigestStart);
assert(
  operationDigestStart >= 0 && operationDigestEnd > operationDigestStart,
  'bridge operation digest function boundary is missing',
);
const operationDigestBody = aggregateBridge.slice(operationDigestStart, operationDigestEnd);
for (const binding of requiredBridgeBindings) {
  if (binding === 'operation-digest') continue;
  assert(
    operationDigestBody.includes(bindingNeedles[binding]),
    `lifecycle bridge operation digest omits ${binding}`,
  );
}
const orderedBindingNeedles = {
  ...bindingNeedles,
  'lifecycle-expiry:unix-seconds': 'lifecycle_expiry.as_secs()',
  'lifecycle-expiry:nanoseconds': 'lifecycle_expiry.subsec_nanos()',
};
let orderedSourceOffset = 0;
for (const descriptor of lifecycleContract.operationDigest.orderedFields) {
  const key = descriptor.component
    ? `${descriptor.binding}:${descriptor.component}`
    : descriptor.binding;
  const needle = orderedBindingNeedles[key];
  assert(typeof needle === 'string', `source needle is missing for ordered binding ${key}`);
  const nextOffset = operationDigestBody.indexOf(needle, orderedSourceOffset);
  assert(nextOffset >= 0, `ordered bridge source field differs: ${key}`);
  orderedSourceOffset = nextOffset + needle.length;
}
const operationEncoderStart = aggregateBridge.indexOf('fn bridge_operation_digest_from_fields(');
const operationEncoderEnd = aggregateBridge.indexOf('\nfn apply_authorized_plan(', operationEncoderStart);
assert(
  operationEncoderStart >= 0 && operationEncoderEnd > operationEncoderStart,
  'shared bridge operation encoder boundary is missing',
);
const operationEncoderBody = aggregateBridge.slice(operationEncoderStart, operationEncoderEnd);
for (const needle of [
  'BridgeOperationField::Required(value) => bridge_field',
  'BridgeOperationField::Optional(value) => bridge_optional_field',
  'BridgeOperationField::U64(value) => bridge_field(&mut bytes, &value.to_be_bytes())',
  'BridgeOperationField::U32(value) => bridge_field(&mut bytes, &value.to_be_bytes())',
  'BridgeOperationField::U16(value) => bridge_field(&mut bytes, &value.to_be_bytes())',
  'domain_digest(BRIDGE_OPERATION_DOMAIN, &bytes)',
]) assert(operationEncoderBody.includes(needle), `shared operation encoder differs: ${needle}`);
const expectedValidatedEqualities = [
  { left: 'identity-resource-count', right: 'lifecycle-object-count' },
  { left: 'authenticated-scope-digest', right: 'idempotency-scope-digest' },
];
assert(
  JSON.stringify(lifecycleContract.validatedEqualities) === JSON.stringify(expectedValidatedEqualities),
  'lifecycle bridge validated-equality registry differs',
);
for (const equality of lifecycleContract.validatedEqualities) {
  assert(
    requiredBridgeBindings.includes(equality.left) && requiredBridgeBindings.includes(equality.right),
    `lifecycle bridge equality has a dangling binding: ${equality.left}/${equality.right}`,
  );
}
const receiptValidationStart = aggregateBridge.indexOf('fn validate_receipt_and_current_settings(');
const receiptValidationEnd = aggregateBridge.indexOf('\nfn bridge_operation_digest(', receiptValidationStart);
assert(
  receiptValidationStart >= 0 && receiptValidationEnd > receiptValidationStart,
  'bridge receipt validation function boundary is missing',
);
const receiptValidationBody = aggregateBridge.slice(receiptValidationStart, receiptValidationEnd);
for (const needle of [
  'receipt.resource_count() != plan.object_count as usize',
  'scope_digest != plan.idempotency_scope_digest',
  'plan.authority_contract_digest != expected_authority_contract',
]) assert(receiptValidationBody.includes(needle), `bridge validated equality is missing: ${needle}`);
assert(lifecycleContract.evidence.aggregateDecisionRows === 1, 'aggregate decision cardinality differs');
assert(lifecycleContract.evidence.aggregateApplicationRows === 1, 'aggregate application cardinality differs');
assert(lifecycleContract.evidence.aggregateOutboxEvents === 1, 'aggregate outbox cardinality differs');
for (const field of ['perResourceFactRows', 'perResourceReachabilityRows', 'perResourceOutboxRows']) {
  const binding = lifecycleContract.evidence[field];
  assert(binding === 'lifecycle-object-count', `${field} cardinality differs`);
  assert(requiredBridgeBindings.includes(binding), `${field} has a dangling binding reference`);
}

const errors = JSON.parse(await readFile(resolve(workspace, 'spec/repository-metadata/v1/registries/domain-errors.json'))).entries;
const errorSource = await readFile(resolve(root, 'src/error.rs'), 'utf8');
for (const error of errors) {
  assert(errorSource.includes(`= ${error.code},`), `Rust domain error code missing: ${error.name}`);
  assert(errorSource.includes(`"${error.name}"`), `Rust domain error name missing: ${error.name}`);
}

const serviceSource = await readFile(resolve(root, 'src/service.rs'), 'utf8');
const metadataDispatcher = await readFile(
  resolve(root, 'src/postgres/metadata_dispatcher.rs'),
  'utf8',
);
const metadataManifestBytes = await readFile(resolve(workspace, 'spec/repository-metadata/v1/manifest.json'));
const metadataManifest = JSON.parse(metadataManifestBytes);
assert(metadataManifest.counts.operations === 22, 'candidate metadata operation count differs');
assert(
  digest(metadataManifestBytes) === '58e595947993900f530fa16a9181f3a064fd66d0363f5ae976017c162a57cdde',
  'candidate metadata manifest identity differs',
);
assert(
  serviceSource.includes('58e595947993900f530fa16a9181f3a064fd66d0363f5ae976017c162a57cdde'),
  'service boundary does not pin the exact candidate manifest',
);
const protocolBindings = JSON.parse(await readFile(resolve(workspace, 'spec/repository-metadata/v1/registries/protocol-bindings.json')));
assert(protocolBindings.profile.id === 'ogvcs.control.https-json@1', 'OGVCS-041 profile differs');
assert(protocolBindings.profile.requestMediaType === 'application/json'
  && protocolBindings.profile.responseMediaType === 'application/json'
  && protocolBindings.profile.errorMediaType === 'application/json', 'OGVCS-041 media profile differs');
assert(protocolBindings.networkRoutes.length === 0
  && protocolBindings.entries.every(({ networkRegistered }) => networkRegistered === false),
  'unwired metadata route entered production registration');
for (const operation of JSON.parse(await readFile(resolve(workspace, 'spec/repository-metadata/v1/registries/operations.json'))).entries) {
  assert(serviceSource.includes(`"${operation.name}"`), `service operation missing: ${operation.name}`);
}
for (const evidence of [
  'pub const PUBLIC_PAGE_ITEMS_MAXIMUM: u16 = 10_000',
  'pub fn parse(bytes: &[u8])',
  'duplicate JSON member',
  'semantic_fingerprint(operation, &body, &extensions)',
  'normalize_json_numbers(&mut value)',
  'idempotency_reservation_at',
  'pub fn require_identity_bound',
  'MetadataOperationExposure::AggregateCoordinatorRequired',
  'MetadataOperationExposure::InternalOnly',
  'Operation::ConformanceWrite',
  'HistoryIncompleteReason::RetentionGap',
  'fn metadata_kind(kind: ObjectKind)',
  'value.contains(\'\\\\\')',
  'PERSISTED_IDENTIFIER_BYTES_MAXIMUM',
  'BoundedJsonBuffer',
  'pub fn problem_response',
  'pub fn verify_negotiation',
  'OGVCS_041_NEGOTIATION_REGISTRY_SET_SHA256',
]) assert(serviceSource.includes(evidence), `public service boundary evidence missing: ${evidence}`);
for (const forbiddenFramework of ['axum::', 'actix_web::', 'hyper::', 'rocket::', '#[get(', '#[post(']) {
  assert(!serviceSource.includes(forbiddenFramework), `unassigned HTTP binding appears: ${forbiddenFramework}`);
}
for (const forbiddenDisclosure of ['eprintln!', 'println!', 'dbg!', 'AuthorizationContext']) {
  assert(
    !metadataDispatcher.includes(forbiddenDisclosure),
    `metadata dispatcher contains a disclosure/bypass surface: ${forbiddenDisclosure}`,
  );
}
assert(
  metadataDispatcher.includes(
    'pub fn dispatch_verified_read(\n        &mut self,\n        verified: NegotiationVerifiedMetadataRequest,\n        credentials: TransactionCredentialRequest',
  ),
  'production metadata dispatcher does not require the negotiation request brand and credential presentation',
);
const dispatchOuterStart = metadataDispatcher.indexOf('    pub fn dispatch_verified_read(');
const dispatchOuterEnd = metadataDispatcher.indexOf('\n    fn dispatch_verified_read_inner(', dispatchOuterStart);
const dispatchOuter = metadataDispatcher.slice(dispatchOuterStart, dispatchOuterEnd);
assert(dispatchOuterStart >= 0 && dispatchOuterEnd > dispatchOuterStart, 'dispatcher public entry boundary is missing');
assert(!dispatchOuter.includes('MetadataOperationRequest'), 'dispatcher accepts a syntax-only metadata request');
assert(
  dispatchOuter.includes('Err(_) => verified')
    && dispatchOuter.includes('MetadataTransportError::AuthorizationDenied'),
  'post-admission dispatcher errors are not mapped to one fixed denial',
);
const dispatchInnerStart = metadataDispatcher.indexOf('    fn dispatch_verified_read_inner(');
const dispatchInnerEnd = metadataDispatcher.indexOf('\n}\n\nfn dispatch_resource(', dispatchInnerStart);
assert(dispatchInnerStart >= 0 && dispatchInnerEnd > dispatchInnerStart, 'dispatcher inner boundary is missing');
const dispatchInner = metadataDispatcher.slice(dispatchInnerStart, dispatchInnerEnd);
for (const requiredBinding of [
  'metadata_negotiation_tenant_digest(tenant_id)',
  'verified.principal().tenant_digest()',
  '.reverify_at(self.negotiation_keys.as_ref(), now_unix_ms)',
  'credential_presentation: credentials.credential_presentation',
  'view.tenant() != tenant',
  'view.repository() != repository',
  'view.authority_epoch() != verified.principal().authority_epoch()',
  'verified.principal().subject_digest()',
  'view.authenticated_scope_digest()',
  'request.minimum_consistency_token()',
  'finalize_identity_decision(',
  'transaction.commit()',
  'CommittedMetadataReadDispatch { _sealed: () }',
]) assert(dispatchInner.includes(requiredBinding), `metadata dispatcher binding missing: ${requiredBinding}`);
const orderedDispatchSteps = [
  'dispatch_resource(request)?',
  '.reverify_at(self.negotiation_keys.as_ref(), now_unix_ms)',
  '.authorize(',
  'SELECT tenant_id FROM ogvcs_metadata.repositories',
  'require_dispatch_consistency(',
  'load_repository_settings(',
  'finalize_identity_decision(',
  'transaction.commit()',
  'CommittedMetadataReadDispatch { _sealed: () }',
];
let dispatchOffset = 0;
for (const step of orderedDispatchSteps) {
  const next = dispatchInner.indexOf(step, dispatchOffset);
  assert(next >= dispatchOffset, `metadata dispatcher ordering differs at: ${step}`);
  dispatchOffset = next + step.length;
}
const resourceStart = metadataDispatcher.indexOf('fn dispatch_resource(');
const resourceEnd = metadataDispatcher.indexOf('\nfn reference_dispatch_resource(', resourceStart);
assert(resourceStart >= 0 && resourceEnd > resourceStart, 'dispatcher resource whitelist boundary is missing');
const resourceBody = metadataDispatcher.slice(resourceStart, resourceEnd);
assert(
  (resourceBody.match(/MetadataOperation::RepositoryGetSettings/gu) ?? []).length === 1
    && (resourceBody.match(/MetadataOperation::ReferenceRead/gu) ?? []).length === 1
    && resourceBody.includes('_ => denied()'),
  'dispatcher operation whitelist is not exactly repository.get-settings/reference.read with closed fallback',
);
const dispatcherContractOperations = JSON.parse(
  await readFile(resolve(workspace, 'spec/repository-metadata/v1/registries/operations.json')),
).entries.filter(({ name }) => ['repository.get-settings', 'reference.read'].includes(name));
assert(
  JSON.stringify(dispatcherContractOperations.map(({ name, permission, resourceType }) => [name, permission, resourceType]))
    === JSON.stringify([
      ['repository.get-settings', 'metadata.read', 'repository'],
      ['reference.read', 'metadata.read', 'reference'],
    ])
    && metadataDispatcher.includes('const METADATA_READ_PERMISSION: &str = "metadata.read";'),
  'dispatcher permission/resource whitelist differs from the authenticated operation registry',
);
assert(
  serviceSource.includes('pub(crate) fn success_for_committed_dispatch(')
    && serviceSource.includes('_committed: crate::postgres::CommittedMetadataReadDispatch'),
  'metadata success construction is not sealed behind a committed dispatch brand',
);
assert(
  serviceSource.includes('pub(crate) fn metadata_negotiation_tenant_digest(')
    && !serviceSource.includes('pub fn metadata_negotiation_tenant_digest('),
  'private tenant projection became a public protocol mapping',
);
const tenantProjection = createHash('sha256')
  .update(Buffer.from('OGVCS-METADATA-NEGOTIATION-TENANT-BINDING-V1\0', 'utf8'))
  .update(Buffer.from('11111111111141119111111111111111', 'hex'))
  .digest('hex');
assert(
  tenantProjection === 'd14c066eb9bd93d48f3506b3c6585c9a2c7d84b3649ccb390ac4f897e6260c9f'
    && serviceSource.includes(tenantProjection),
  'private tenant projection golden differs between Node and Rust',
);
const referenceKind = Buffer.from('branch', 'utf8');
const referenceName = Buffer.from('main', 'utf8');
const referenceProjection = createHash('sha256')
  .update(Buffer.from('OGVCS-METADATA-REFERENCE-DISPATCH-RESOURCE-V1\0', 'utf8'))
  .update(encodeUnsigned(referenceKind.length, 8, 'reference kind byte length'))
  .update(referenceKind)
  .update(encodeUnsigned(referenceName.length, 8, 'reference name byte length'))
  .update(referenceName)
  .digest('hex');
assert(
  referenceProjection === '018091fc8353e10067e61086bb9c21889eb805c3c9ef179505202658450afc18'
    && metadataDispatcher.includes('REFERENCE_DISPATCH_RESOURCE_DOMAIN')
    && metadataDispatcher.includes('(kind.len() as u64).to_be_bytes()')
    && metadataDispatcher.includes('(name.as_str().len() as u64).to_be_bytes()'),
  'private reference projection framing differs between Node and Rust',
);
const serviceContractTests = await readFile(resolve(root, 'tests/service_contract.rs'), 'utf8');
for (const evidence of [
  'all_twenty_two_request_variants_are_validated_and_bound',
  'public_page_and_consistency_token_boundaries_are_exact',
  'coordinator_and_internal_mutations_cannot_enter_identity_bound_dispatch',
  'semantic_idempotency_is_order_independent_but_operation_and_body_bound',
  'malformed_duplicate_and_over_limit_inputs_fail_before_dispatch',
  'object_stream_operations_admit_only_repository_metadata_kinds',
  'response_constructors_bind_shapes_limits_and_non_disclosure',
]) assert(serviceContractTests.includes(evidence), `public service regression missing: ${evidence}`);
const responseType = await readFile(resolve(root, 'src/types.rs'), 'utf8');
assert(responseType.includes('pub(crate) schema_version:'), 'response envelope fields remain publicly forgeable');
assert(responseType.includes('RetentionGap'), 'retention-gap page result is not represented');

const expandV1Bytes = await readFile(resolve(migrations, '000001_expand.sql'));
const expand = expandV1Bytes.toString('utf8');
assert(digest(expandV1Bytes) === '58b53c7cd61b5f8b0e6fca4184a36379c049947a34751bedb1bd77ded674d53c', 'version 1 migration identity was rewritten');
assert(expand.includes('object_kind IN (2, 3, 4, 5, 6, 7, 9, 10, 11)'), 'metadata kind allowlist omits manifests or includes an unexpected kind');
assert(!expand.includes('object_kind IN (1,'), 'chunk bytes entered metadata ownership');
assert(expand.includes('FOREIGN KEY (repository_id, tree_kind, tree_algorithm, tree_digest)'), 'tree entry owner is not tied to kind-3 metadata');
assert(expand.includes("resource_type IN ('repository', 'reference', 'snapshot', 'tree', 'path')"), 'outbox resource types differ from the domain registry');
const expandV2 = await readFile(resolve(migrations, '000002_expand.sql'), 'utf8');
const migrateV2 = await readFile(resolve(migrations, '000002_migrate.sql'), 'utf8');
assert(expandV2.includes('CREATE TRIGGER repository_settings_immutable'), 'immutable repository settings trigger missing from version 2');
assert(expandV2.includes('file_path_history_by_file_id_v2'), 'version 2 history index missing operation ordinal');
assert(
  !expandV2.includes('published_commit_sequence')
    && !migrateV2.includes('published_commit_sequence'),
  'version 2 infers historical publication markers',
);
const expandV3 = await readFile(resolve(migrations, '000003_expand.sql'), 'utf8');
assert(expandV3.includes('outbox_events_lease_complete'), 'version 3 complete outbox lease invariant missing');
assert(expandV3.includes('acknowledged_at'), 'version 3 outbox acknowledgement state missing');
assert(expandV3.includes('WHERE acknowledged_at IS NULL'), 'version 3 deliverable index includes acknowledged events');
const expandV4 = await readFile(resolve(migrations, '000004_expand.sql'), 'utf8');
assert(expandV4.includes('bounded_snapshot_ancestry'), 'version 4 bounded ancestry primitive missing');
assert(expandV4.includes('requested_maximum_work > 100001'), 'version 4 history work cap missing');
assert(expandV4.includes('ORDER BY parent.ordinal'), 'version 4 parent order is not deterministic');
const expandV5 = await readFile(resolve(migrations, '000005_expand.sql'), 'utf8');
assert(expandV5.includes('repository_list_cursor_states'), 'version 5 project cursor ledger missing');
assert(expandV5.includes('position_repository_id uuid'), 'version 5 project cursor position missing');
const expandV6 = await readFile(resolve(migrations, '000006_expand.sql'), 'utf8');
assert(expandV6.includes('file_id_allocation_receipts'), 'version 6 allocation receipt ledger missing');
assert(expandV6.includes('authenticated_scope_digest'), 'allocation receipt is not bound to authenticated scope');
assert(expandV6.includes('consumed_at'), 'allocation receipt is not one-use');
const expandV7 = await readFile(resolve(migrations, '000007_expand.sql'), 'utf8');
assert(expandV7.includes('ogvcs_metadata.consistency_tokens'), 'version 7 consistency-token scope migration missing');
assert(expandV7.includes('ogvcs_metadata.cursor_states'), 'version 7 repository cursor scope migration missing');
assert(expandV7.includes('ogvcs_metadata.repository_list_cursor_states'), 'version 7 project cursor scope migration missing');
assert(expandV7.includes('authenticated_scope_digest'), 'version 7 token state is not bound to authenticated scope');
const expandV8 = await readFile(resolve(migrations, '000008_expand.sql'), 'utf8');
assert(expandV8.includes('authorization_reference'), 'version 8 replay reference binding missing');
assert(expandV8.includes('authorization_resources'), 'version 8 replay resource binding missing');
assert(expandV8.includes('authorization_binding_digest'), 'version 8 replay integrity binding missing');
assert(expandV8.includes('octet_length(authorization_resources::text) <= 8388608'), 'version 8 replay batch byte bound missing');
assert(expandV8.includes('octet_length(safe_result::text) <= 1048576'), 'version 8 replay result byte bound missing');
assert(expandV8.includes('idempotency_identity_safe_result_bounded'), 'version 8 identity result constraint missing');
assert(expandV8.includes('authorization_resources IS NULL\n            OR safe_result IS NULL'), 'version 8 does not preserve oversized authority-null legacy results');
const expandV9 = await readFile(resolve(migrations, '000009_expand.sql'), 'utf8');
for (const evidence of [
  'object_lifecycle',
  'lifecycle_receipts',
  'lifecycle_receipt_consumptions',
  'lifecycle_publication_plan_chunks',
  'lifecycle_publication_plan_items',
  'lifecycle_publication_plan_seals',
  'lifecycle_applications',
  'lifecycle_publication_reachability',
  'lifecycle_deletion_fences',
  'lifecycle_internal_outbox',
  'current_health_observation_digest',
  'resource_opaque_digest',
  'FOR UPDATE OF lifecycle',
]) assert(expandV9.includes(evidence), `version 9 lifecycle evidence missing: ${evidence}`);
assert(expandV9.includes("(health = 'not-applicable')\n           = (health_generation IS NULL AND health_observation_digest IS NULL)"), 'version 9 lifecycle health axis differs');
assert(!expandV9.includes('FOR item_row IN'), 'version 9 aggregate validation contains a per-item SQL loop');
const expandV10 = await readFile(resolve(migrations, '000010_expand.sql'), 'utf8');
for (const evidence of [
  'lifecycle_aggregate_authorization_evidence',
  'aggregate_plan_consumptions',
  'NEW.context_digest = evidence.operation_digest',
  'identity_plan.signer_key_reference = evidence.signer_key_reference',
  'EXTRACT(EPOCH FROM identity_plan.issued_at)',
  'EXTRACT(EPOCH FROM identity_plan.expires_at)',
  'resource_digest_projection_digest',
  'lifecycle_expires_at',
  'aggregate_event) = 1',
  'reject_sealed_aggregate_child_insert_v10',
  'lifecycle_transaction_facts_aggregate_sealed_v10',
  'lifecycle_reachability_aggregate_sealed_v10',
  'lifecycle_outbox_aggregate_sealed_v10',
]) assert(expandV10.includes(evidence), `version 10 aggregate bridge evidence missing: ${evidence}`);
const expandV11 = await readFile(resolve(migrations, '000011_expand.sql'), 'utf8');
for (const predecessor of [
  '69cd3b10a60be43f8aeb2214f18df50124f143a242e1a46f72afac10067d976e',
  '1d9691bbf721c888f52981d71bf9727a76c1f2825837bc8ba2f98bb5d00150f5',
  '8526bcffb01289747a7e6de61adcedb0b81788b80738d75850635d2f441b4974',
]) assert(expandV11.includes(predecessor), `version 11 predecessor pin missing: ${predecessor}`);
for (const evidence of [
  'submit_intents',
  'operation_count BETWEEN 1 AND 1000',
  "operation_kind IN ('create', 'copy', 'import')",
  'candidate_change_set_digest',
  'submit_file_id_consumptions',
  'UNIQUE (repository_id, file_id)',
  'submit operation set is sealed',
  'submit FileID evidence is sealed',
  'consumption.prior_owner_kind = operation.prior_owner_kind',
  'consumption.prior_owner_id = operation.prior_owner_id',
  'submit_outcome_complete_v11',
]) assert(expandV11.includes(evidence), `version 11 private atomic-submit evidence missing: ${evidence}`);
assert(expandV11.includes('repository metadata v11 predecessor authority mismatch'), 'version 11 predecessor fence missing');
assert(!expandV11.includes('NEW.operation_count = 0 OR'), 'version 11 admits an unproved zero-operation submit');

const atomicSubmitAdapter = await readFile(resolve(root, 'src/postgres/atomic_submit.rs'), 'utf8');
assert(atomicSubmitAdapter.includes('finalize_preallocated_creation_submit'), 'private preallocated creation-submit finalize boundary missing');
assert(atomicSubmitAdapter.includes('FOR UPDATE OF registry'), 'FileID rows are not locked for first consumption');
assert(atomicSubmitAdapter.includes('ORDER BY operation.operation_ordinal'), 'FileID lock order is not deterministic');
assert(atomicSubmitAdapter.includes('apply_aggregate_lifecycle_publication_in_transaction'), 'atomic submit does not use the caller-owned bridge');
assert(atomicSubmitAdapter.includes('submit_file_id_consumptions'), 'atomic submit omits permanent FileID evidence');
assert(!atomicSubmitAdapter.includes('spec/atomic-submit'), 'private candidate invents a public submit contract');

const lifecycleAdapter = await readFile(resolve(root, 'src/postgres/lifecycle.rs'), 'utf8');
assert(lifecycleAdapter.includes('FROM unnest('), 'version 9 chunk writer is not set based');
assert(lifecycleAdapter.includes('command.capability != LifecycleCapability::SubmitConsumePublication'), 'publish transaction accepts a non-submit lifecycle capability');
assert(!lifecycleAdapter.includes('hmac_sha256(&command.idempotency_scope_digest'), 'non-secret idempotency material is used as an authority MAC key');
assert(
  lifecycleAdapter.split('crate::verify_schema_compatibility(&mut self.client)?').length - 1 === 5,
  'every lifecycle store entry point is not schema-compatibility gated',
);
for (const forbiddenBackendAccess of ['reqwest::', 'aws_sdk_', 'std::fs::', 'tokio::net::']) {
  assert(
    !lifecycleAdapter.includes(forbiddenBackendAccess),
    `external backend access appears in the final metadata adapter: ${forbiddenBackendAccess}`,
  );
}

const adapter = await readFile(resolve(root, 'src/postgres.rs'), 'utf8');
assert(
  adapter.includes('TransactionCapability::CreateRepository\n                | TransactionCapability::Publish'),
  'production identity boundary admits partial repository creation',
);
const ports = await readFile(resolve(root, 'src/ports.rs'), 'utf8');
assert(
  adapter.split('crate::verify_schema_compatibility(&mut self.client)?').length - 1 === 19,
  'every mutation/read entry point is not schema-compatibility gated',
);
assert(ports.includes('ValidationMode::Production'), 'default object validator is not production lifecycle');
assert(ports.includes('type AuthorizedView: AuthorizedView'), 'authorizer output is not an exact view contract');
assert(ports.includes('resource: &AuthorizationResource'), 'authorizer is not bound to a typed resource projection');
assert(adapter.includes('#[cfg(feature = "legacy-test-adapter")]\n    pub fn connect(database_url: &str)'), 'caller-context store constructor is available in the default build');
for (const sealedAccessor of ['authorized_repository_id', 'authorization_context', 'authorized_view']) {
  assert(
    adapter.includes(`#[cfg(feature = "legacy-test-adapter")]\n    pub fn ${sealedAccessor}`),
    `production transaction exposes ${sealedAccessor}`,
  );
}
assert(adapter.includes('} if *repository_id == self.repository_id && *capability == self.capability'), 'identity authorized view is not restricted to its bootstrap capability');
assert(adapter.includes('#[cfg(feature = "legacy-test-adapter")]\n    pub fn idempotency_status('), 'legacy committed-status API is exposed by default');
assert(adapter.includes('impl IdentityBoundPostgresMetadataStore<DenyAllAuthorization, ProductionObjectValidator>'), 'production identity-bound constructor is missing');
assert(adapter.includes('pub fn connect(\n        database_url: &str,\n        participant: PostgresTransactionAuthorizationParticipant,'), 'production constructor does not require the OGVCS-009 participant');
for (const evidence of [
  'pub fn begin_authorized(',
  'pub fn execute_serializable<T>(',
  'ON CONFLICT DO NOTHING RETURNING 1',
  'generation = generation + 1',
  'published_commit_sequence IS NULL',
  'KeyReuseRejected',
  'authorized_repository_id: RepositoryId',
  'authorization_context: AuthorizationContext',
  'authorized_view: View',
  'capability: TransactionCapability',
  'AuthorizationResource::RepositoryTransaction',
  'finish_committed_replay',
  'outbox_events: Vec<RequiredOutboxEvent>',
  'fact.resource_opaque_id(event.repository_id, event.event_id, &safe_payload)',
  'valid_public_uuid(&event.event_id)',
  'self.outbox_events.iter().any(|event| !event.emitted)',
  'MAX_REQUIRED_OUTBOX_EVENTS',
  'MAX_JSON_PREFLIGHT_DEPTH',
  'MAX_JSON_PREFLIGHT_NODES',
  'self.mutation_started && !self.idempotency_committed',
  'reservation.is_valid_at(server_now)',
  'idempotency_scope_digest',
  'capability.as_str().as_bytes()',
  'pub fn allocate_file_id(',
  'consume_allocation_receipt',
  'authenticated_scope_digest = $2',
  'pub fn idempotency_status(',
  'repository_object_matches_settings',
  'descriptor_matches_repository_settings',
  'validation_contract != VALIDATION_CONTRACT',
  'validate_publication_candidate',
  'validate_repository_candidate(candidate, &context)',
  'metadata_closure(&entries, candidate)',
  'candidate_tree_file_ids(&entries, candidate)',
  'first_change_set_digest = $3',
  'validate_snapshot_graph(candidate, &context)',
  'enforce_configured_tree_limits',
  'canonical_file_history_from_change',
  'expected_state.as_str()',
  'MAX_AUTHORIZATION_SCAN',
  'AuthorizationResource::TreeEntry',
  'AuthorizationResource::FileHistoryEntry',
  'authorized_view.permits(context',
  'require_repository_tenant',
  'require_published_snapshot_tree',
  'pub fn get_repository_settings(',
  'pub fn repository_page(',
  'AuthorizationResource::ProjectRepository',
  'repository_list_cursor_states',
  'pub fn get_object(',
  'AuthorizationResource::MetadataObject',
  'pub fn tree_page_consistent(',
  'pub fn reference_page_filtered(',
  'pub fn file_history_page_consistent(',
  'pub fn ancestry_page(',
  'pub fn history_file_id_page(',
  'pub fn history_path_page(',
  'AuthorizationResource::SnapshotHistoryEntry',
  'AuthorizationResource::SnapshotFileHistoryEntry',
  'MAX_HISTORY_WORK',
  'HistoryIncompleteReason::DepthLimit',
  'HistoryIncompleteReason::WorkLimit',
  'ReferenceFilter::Kind',
  'resolve_tree_prefix',
  'valid_tree_prefix',
  'traversed_edges > limits.max_edges',
  'snapshot.published_commit_sequence',
  'matches!(existing_state.as_str(), "reserved" | "active")',
  'snapshot.published_commit_sequence > 0',
  'is_database_concurrency()',
  '"40001" | "40P01"',
  'clock_timestamp() + interval \'5 minutes\'',
  'FOR UPDATE SKIP LOCKED',
  'MetadataPermission::ServiceInternal',
  'acknowledged_at IS NULL',
  'lease_expires_at > clock_timestamp()',
  'ORDER BY basename_utf8',
  'ORDER BY reference.reference_kind, reference.reference_name',
  'ORDER BY history.snapshot_digest, history.operation_ordinal',
]) assert(adapter.includes(evidence), `PostgreSQL adapter evidence missing: ${evidence}`);

const liveContract = await readFile(resolve(root, 'tests/postgres_integration.rs'), 'utf8');
assert(liveContract.includes('CollectionOnlyAllow'), 'item-level AuthorizedView denial regression missing');
assert(liveContract.includes('authorized-view-item-projections'), 'projection non-disclosure report missing');
assert(liveContract.includes('CapabilityMisbindingAllow'), 'transaction capability-misbinding regression missing');
assert(liveContract.includes('RevocableAllow'), 'authorized-view revocation regression missing');
assert(liveContract.includes('SingleUseAllow'), 'read-view revalidation regression missing');
assert(liveContract.includes('missing-publication-marker'), 'publication-marker fail-closed regression missing');
assert(liveContract.includes('restore-capability-alias'), 'restore capability alias regression missing');
assert(liveContract.includes('file-import-tampered-owner'), 'import replay binding regression missing');

const types = await readFile(resolve(root, 'src/types.rs'), 'utf8');
for (const permission of ['"discover"', '"metadata.read"', '"submit"', '"service-internal"']) {
  assert(types.includes(permission), `canonical permission missing: ${permission}`);
}
const outboxInputStart = types.indexOf('pub struct OutboxEvent {');
const outboxInputEnd = types.indexOf('\n}', outboxInputStart);
assert(outboxInputStart >= 0 && outboxInputEnd > outboxInputStart, 'outbox input type missing');
const outboxInput = types.slice(outboxInputStart, outboxInputEnd);
for (const forbiddenCallerField of [
  'pub event_type:',
  'pub event_version:',
  'pub resource_type:',
  'pub resource_opaque_id:',
  'pub safe_payload:',
]) {
  assert(!outboxInput.includes(forbiddenCallerField), `caller still controls outbox fact: ${forbiddenCallerField}`);
}

for (const method of [
  'create_repository',
  'put_object',
  'index_tree_entry',
  'index_snapshot',
  'append_file_history',
  'reserve_file_id',
  'reserve_imported_file_id',
  'activate_file_id',
  'tombstone_file_id',
  'reserve_idempotency',
  'commit_idempotency',
  'compare_and_swap_reference',
  'append_outbox',
  'issue_consistency_token',
]) {
  const start = adapter.indexOf(`    fn ${method}(`);
  const end = adapter.indexOf('\n    fn ', start + 8);
  assert(start >= 0, `transaction method missing: ${method}`);
  assert(
    adapter.slice(start, end < 0 ? adapter.length : end).includes('poison_transaction_on_error!'),
    `transaction method does not poison every Err: ${method}`,
  );
}
assert(
  adapter.indexOf('reservation.origin == FileIdOrigin::Restore')
    < adapter.indexOf('INSERT INTO ogvcs_metadata.file_id_registry'),
  'generic FileID restore is not rejected before SQL',
);
{
  const start = adapter.indexOf('    fn reserve_file_id(');
  const end = adapter.indexOf('\n    fn reserve_imported_file_id(', start);
  assert(
    start >= 0 && end > start
      && !adapter.slice(start, end).includes('TransactionCapability::RestoreFileId'),
    'restore capability can alias generic FileID reservation',
  );
}

const migrationRunner = await readFile(resolve(root, 'src/migration_runner.rs'), 'utf8');
assert(migrationRunner.includes('pub fn verify_schema_compatibility'), 'mutation schema compatibility gate missing');
assert(
  migrationRunner.indexOf('let existing =') < migrationRunner.indexOf('migration.requires_compatibility_fence'),
  'closed migration fence bypasses ledger checksum validation',
);

const reportDriver = await readFile(resolve(root, 'scripts/service-report.mjs'), 'utf8');
assert(reportDriver.includes('exactScaleExecuted: false'), 'service report does not exclude exact scale');
assert(reportDriver.includes('OGVCS_METADATA_DATABASE_URL is unset'), 'service report does not declare database skip');

process.stdout.write(`statically verified repository-metadata Rust/SQL scaffold: ${rustFiles.length} Rust modules, ${manifest.entries.length} migrations, ${errors.length} errors\n`);
