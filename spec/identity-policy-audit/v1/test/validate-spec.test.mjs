import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { cp, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { validateIdentityPolicyContract } from '../validate-spec.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');
const ordered = (value) => Array.isArray(value) ? value.map(ordered)
  : value !== null && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, ordered(value[key])]))
    : value;
const canonical = (value) => `${JSON.stringify(ordered(value))}\n`;
const setDigest = (entries) => digest(canonical(entries
  .map(({ path, sha256 }) => ({ path, sha256 }))
  .sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0)));

async function reauthenticate(directory, relative, mutate) {
  const target = join(directory, relative);
  const value = JSON.parse(await readFile(target, 'utf8'));
  mutate(value);
  const bytes = canonical(value);
  await writeFile(target, bytes, 'utf8');
  const manifestPath = join(directory, 'manifest.json');
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
  const artifact = manifest.artifacts.find(({ path }) => path === relative);
  artifact.bytes = Buffer.byteLength(bytes);
  artifact.sha256 = digest(bytes);
  if (relative.startsWith('schemas/')) {
    const registryPath = join(directory, 'registries', 'schemas.json');
    const registry = JSON.parse(await readFile(registryPath, 'utf8'));
    const entry = registry.entries.find(({ path }) => path === relative);
    entry.bytes = artifact.bytes;
    entry.sha256 = artifact.sha256;
    const registryBytes = canonical(registry);
    await writeFile(registryPath, registryBytes, 'utf8');
    const registryArtifact = manifest.artifacts.find(({ path }) => path === 'registries/schemas.json');
    registryArtifact.bytes = Buffer.byteLength(registryBytes);
    registryArtifact.sha256 = digest(registryBytes);
  }
  manifest.artifactSetSha256 = setDigest(manifest.artifacts);
  manifest.registrySetSha256 = setDigest(manifest.artifacts.filter(({ path }) => path.startsWith('registries/')));
  manifest.schemaSetSha256 = setDigest(manifest.artifacts.filter(({ path }) => path.startsWith('schemas/')));
  manifest.vectorSetSha256 = setDigest(manifest.artifacts.filter(({ path }) => path.startsWith('vectors/')));
  await writeFile(manifestPath, canonical(manifest), 'utf8');
}

test('generated identity-policy contract is authenticated and bounded', async () => {
  const result = await validateIdentityPolicyContract(root);
  assert.equal(result.artifacts, 21);
  assert.equal(result.vectors, 29);
});

test('contract validation rejects schema tampering', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'ogvcs-identity-contract-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  await cp(root, directory, { recursive: true });
  const target = join(directory, 'schemas', 'CredentialRecord.schema.json');
  const source = await readFile(target, 'utf8');
  await writeFile(target, source.replace('digest-only', 'plaintext-ok'), 'utf8');
  await assert.rejects(() => validateIdentityPolicyContract(directory), /artifact (?:length differs|authentication failed)/u);
});

test('contract imports predecessor assignments and leaves public protocol binding unassigned', async () => {
  const [manifest, policy, audit] = await Promise.all([
    readFile(join(root, 'manifest.json'), 'utf8').then(JSON.parse),
    readFile(join(root, 'schemas', 'PolicyDocument.schema.json'), 'utf8').then(JSON.parse),
    readFile(join(root, 'schemas', 'AuditChainRecord.schema.json'), 'utf8').then(JSON.parse),
  ]);
  assert.equal(manifest.protocolBinding, 'unassigned-future-release-required');
  assert.equal(policy['x-ogvcs-imported-assignments'].permissions, 'ogvcs.authorization@1/permissions');
  assert.match(audit.properties.event.$ref, /authorization\/v1\/AuditEvent/u);
});

test('independent validation rejects a reauthenticated non-HTTPS OIDC authority', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'ogvcs-identity-oidc-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  await cp(root, directory, { recursive: true });
  await reauthenticate(directory, 'schemas/OidcProvider.schema.json', (value) => {
    value.properties.issuer.pattern = '^.+$';
  });
  await assert.rejects(() => validateIdentityPolicyContract(directory), /OIDC endpoint is not HTTPS-only/u);
});

test('independent validation rejects a reauthenticated production-vector substitution', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'ogvcs-identity-vector-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  await cp(root, directory, { recursive: true });
  await reauthenticate(directory, 'vectors/production-boundaries.json', (value) => {
    value.cases.find(({ id }) => id === 'transaction-decision-commitment-same-tx').expected = 'best-effort';
  });
  await assert.rejects(() => validateIdentityPolicyContract(directory), /vector inventory differs/u);
});
