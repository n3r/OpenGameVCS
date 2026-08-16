import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  createCompactTransferGrant,
  decodeCompactTransferGrant,
  inspectRequestRootGrant,
  loadAuthorizationGrantContract,
  loadProtocolContract,
  validateCompactTransferGrant,
  validateRequestRootGrant,
} from '../src/index.mjs';
import { authorizationRoot, protocolRoot } from './roots.mjs';

function envelope(overrides = {}) {
  return {
    schemaVersion: 'ogvcs.authorization/transfer-grant/v1',
    algorithm: 'Ed25519',
    keyId: 'test-key',
    claims: {
      schemaVersion: 'ogvcs.authorization/transfer-grant-claims/v1',
      issuer: 'issuer', keyId: 'test-key', keyGeneration: 1, authorityEpoch: 2,
      subject: 'subject', tenant: 'tenant', repository: 'repository',
      permission: 'content.materialize', operation: 'download', audience: 'transfer',
      issuedAt: 10, expiresAt: 20, nonce: 'nonce', replay: 'single-use',
      objectIds: [], requestRoot: `sha256:${'ab'.repeat(32)}`,
      ...overrides,
    },
    signature: 'A'.repeat(86),
  };
}

test('grant loader verifies public authorization schema artifacts', async () => {
  const contract = await loadAuthorizationGrantContract({ root: authorizationRoot, cache: false });
  assert.equal(contract.manifest.contractVersion, '1.0.0');
  assert.match(contract.registrySetSha256, /^[0-9a-f]{64}$/u);
});

test('compact carrier accepts only request-root grants with an empty explicit set', async () => {
  const contract = await loadAuthorizationGrantContract({ root: authorizationRoot });
  const inspected = inspectRequestRootGrant(envelope(), contract);
  assert.match(inspected.sha256, /^[0-9a-f]{64}$/u);
  assert.equal(inspected.envelope.claims.objectIds.length, 0);
  assert.throws(() => inspectRequestRootGrant(envelope({ objectIds: ['sha256:item'], requestRoot: null }), contract), /compact request-root/u);
});

test('protocol carrier delegates issuer, key, epoch, scope, expiry, and replay semantics to the authorization verifier', async () => {
  const contract = await loadAuthorizationGrantContract({ root: authorizationRoot });
  let calls = 0;
  const result = await validateRequestRootGrant(envelope(), contract, async (supplied, context) => {
    calls += 1;
    assert.equal(supplied.claims.authorityEpoch, 2);
    assert.equal(context.operation, 'TransferProbe');
    return { result: 'allow', code: 'ALLOW_EXPLICIT' };
  }, { operation: 'TransferProbe' });
  assert.equal(calls, 1);
  assert.equal(result.envelope.claims.requestRoot, `sha256:${'ab'.repeat(32)}`);
  await assert.rejects(() => validateRequestRootGrant(envelope(), contract, async () => false, {}), /grant is invalid/u);
  for (const code of ['ALLOW_PUBLIC', 'ALLOW_FAKE']) {
    await assert.rejects(
      () => validateRequestRootGrant(envelope(), contract, async () => ({ result: 'allow', code }), {}),
      /grant is invalid/u,
      code,
    );
  }
});

test('grant validation is bounded and rejects before verifier invocation', async () => {
  const contract = await loadAuthorizationGrantContract({ root: authorizationRoot });
  let called = false;
  await assert.rejects(
    () => validateRequestRootGrant(envelope({ objectIds: ['x'], requestRoot: null }), contract, async () => { called = true; return { result: 'allow', code: 'ALLOW_EXPLICIT' }; }, {}),
    /compact request-root/u,
  );
  assert.equal(called, false);
  assert.throws(() => inspectRequestRootGrant({ ...envelope(), extra: true }, contract), /registered property/u);
});

test('authorization schema cache remains partitioned by receiver ceiling', async () => {
  await loadAuthorizationGrantContract({ root: authorizationRoot });
  await assert.rejects(() => loadAuthorizationGrantContract({ root: authorizationRoot, maxAssetBytes: 64 }), /bounded regular file/u);
});

test('authorization loader and inbound compact carrier enforce the exact protocol predecessor pin', async (t) => {
  const protocol = await loadProtocolContract({ root: protocolRoot });
  const authorization = await loadAuthorizationGrantContract({ root: authorizationRoot });
  const carrier = createCompactTransferGrant(protocol, authorization, envelope());
  assert.equal(decodeCompactTransferGrant(protocol, authorization, carrier).envelope.claims.subject, 'subject');
  let calls = 0;
  await validateCompactTransferGrant(protocol, authorization, carrier, async () => { calls += 1; return { result: 'allow', code: 'ALLOW_EXPLICIT' }; }, {});
  assert.equal(calls, 1);

  const alternateManifest = { ...authorization, manifestSha256: '00'.repeat(32) };
  assert.throws(() => decodeCompactTransferGrant(protocol, alternateManifest, carrier), /predecessor pin/u);
  assert.throws(() => createCompactTransferGrant(protocol, { ...authorization, registrySetSha256: '11'.repeat(32) }, envelope()), /predecessor pin/u);
  const alternateProtocol = {
    ...protocol,
    manifest: {
      ...protocol.manifest,
      predecessorPins: {
        ...protocol.manifest.predecessorPins,
        authorization: { ...protocol.manifest.predecessorPins.authorization, contractVersion: '9.9.9' },
      },
    },
  };
  assert.throws(() => decodeCompactTransferGrant(alternateProtocol, authorization, carrier), /predecessor pin/u);

  const directory = await mkdtemp(join(tmpdir(), 'ogvcs-authz-pin-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  await writeFile(join(directory, 'manifest.json'), `${JSON.stringify({ ...authorization.manifest, contractVersion: '9.9.9' })}\n`);
  await assert.rejects(() => loadAuthorizationGrantContract({ root: directory, cache: false }), /manifest envelope/u);
});
