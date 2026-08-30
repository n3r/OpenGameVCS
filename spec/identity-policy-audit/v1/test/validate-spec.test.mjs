import assert from 'node:assert/strict';
import { cp, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { validateIdentityPolicyContract } from '../validate-spec.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));

test('generated identity-policy contract is authenticated and bounded', async () => {
  const result = await validateIdentityPolicyContract(root);
  assert.equal(result.artifacts, 11);
  assert.equal(result.vectors, 15);
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
