#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const defaultRoot = dirname(fileURLToPath(import.meta.url));
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');
const assert = (condition, message) => { if (!condition) throw new Error(message); };
const unique = (values) => new Set(values).size === values.length;

export async function validateIdentityPolicyContract(root = defaultRoot) {
  const manifestBytes = await readFile(resolve(root, 'manifest.json'));
  const manifest = JSON.parse(manifestBytes);
  assert(manifest.schemaVersion === 'ogvcs.identity-policy/contract-manifest/v1', 'manifest schema is invalid');
  assert(manifest.contractVersion === '0.1.0' && manifest.state === 'candidate', 'contract lifecycle differs');
  assert(manifest.protocolBinding === 'unassigned-future-release-required', 'candidate claimed a frozen protocol assignment');
  for (const artifact of manifest.artifacts) {
    const bytes = await readFile(resolve(root, artifact.path));
    assert(bytes.length === artifact.bytes, `artifact length differs: ${artifact.path}`);
    assert(digest(bytes) === artifact.sha256, `artifact authentication failed: ${artifact.path}`);
  }

  const limits = JSON.parse(await readFile(resolve(root, 'registries/limits.json')));
  assert(limits.registry === 'limits' && limits.entries.length === manifest.counts.limits, 'limit registry differs');
  assert(unique(limits.entries.map(({ code }) => code)) && unique(limits.entries.map(({ name }) => name)), 'limit assignments repeat');
  const byName = Object.fromEntries(limits.entries.map(({ name, value }) => [name, value]));
  assert(byName.sessionMaxTtlSeconds <= 28_800, 'session validity exceeds OGVCS-003');
  assert(byName.serviceTokenMaxTtlSeconds <= 3_600, 'service validity exceeds OGVCS-003');
  assert(byName.transferGrantMaxTtlSeconds <= 300, 'grant validity exceeds OGVCS-003');

  const policy = JSON.parse(await readFile(resolve(root, 'schemas/PolicyDocument.schema.json')));
  assert(policy.properties.default.const === 'deny' && policy.properties.composition.const === 'deny-overrides-v1', 'policy does not fail closed');
  assert(policy.properties.rules.maxItems === byName.maxPolicyRules, 'policy bound differs');
  assert(policy['x-ogvcs-imported-assignments'].permissions === 'ogvcs.authorization@1/permissions', 'policy duplicated permission authority');
  assert(!Object.hasOwn(policy.properties.rules.items.properties, 'operations'), 'policy invented an operation vocabulary');
  const credential = JSON.parse(await readFile(resolve(root, 'schemas/CredentialRecord.schema.json')));
  assert(Object.hasOwn(credential.properties, 'secretDigest') && !Object.hasOwn(credential.properties, 'secret'), 'credential schema persists plaintext');
  const audit = JSON.parse(await readFile(resolve(root, 'schemas/AuditChainRecord.schema.json')));
  assert(audit.properties.event.$ref.endsWith('/AuditEvent.schema.json'), 'audit event does not import OGVCS-003');
  assert(audit.properties.previousHash.oneOf.some(({ type }) => type === 'null'), 'audit genesis is undefined');
  const checkpoint = JSON.parse(await readFile(resolve(root, 'schemas/AuditCheckpoint.schema.json')));
  assert(checkpoint.properties.tailHash.oneOf.some(({ type }) => type === 'null')
    && checkpoint['x-ogvcs-trust-boundary'].includes('outside'), 'audit checkpoint trust boundary is undefined');
  const auditView = JSON.parse(await readFile(resolve(root, 'schemas/AuthorizedAuditView.schema.json')));
  const auditEvent = JSON.parse(await readFile(resolve(root, 'schemas/AuthorizedAuditEvent.schema.json')));
  assert(auditView.properties.items.maxItems === byName.maxAuditQueryRecords
    && auditView['x-ogvcs-requires'].includes('externally retained checkpoint'), 'authorized audit view bound differs');
  assert(auditEvent['x-ogvcs-privacy'].includes('no tenant-global chain position')
    && !Object.hasOwn(auditEvent.properties, 'sequence')
    && !Object.hasOwn(auditEvent.properties, 'recordHash'), 'authorized audit event exposes chain position');

  const vectors = JSON.parse(await readFile(resolve(root, 'vectors/security-core.json'))).cases;
  assert(vectors.length === manifest.counts.vectors && unique(vectors.map(({ id }) => id)), 'vector inventory differs');
  for (const required of ['malformed-path-fails-closed', 'authorized-view-hides-paths-and-counts', 'session-stale-epoch', 'service-token-revoked', 'transfer-grant-revoked', 'audit-chain-tamper', 'cross-tenant-path-enumeration', 'rate-limit-before-lookup', 'policy-rule-resource-bound']) {
    assert(vectors.some(({ id }) => id === required), `security vector missing: ${required}`);
  }

  const workspace = resolve(root, '../../..');
  for (const pin of Object.values(manifest.predecessorPins)) {
    const bytes = await readFile(resolve(workspace, pin.manifestPath));
    assert(digest(bytes) === pin.manifestSha256, `predecessor pin drifted: ${pin.authority}`);
  }
  return Object.freeze({ manifestSha256: digest(manifestBytes), artifacts: manifest.artifacts.length, vectors: vectors.length });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const result = await validateIdentityPolicyContract();
  process.stdout.write(`validated identity-policy contract ${result.manifestSha256}: ${result.artifacts} artifacts, ${result.vectors} vectors\n`);
}
