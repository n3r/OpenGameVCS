import assert from 'node:assert/strict';
import test from 'node:test';

import {
  AuthorizationContractError,
  canonicalJson,
  executeReferenceVector,
  parseCanonicalJson,
  validateAuthorizationRequest,
  validateThreatVector,
  validateTransferGrantClaims,
} from '../src/index.mjs';

test('deep hostile JSON is rejected with a typed ceiling before recursive encoding', () => {
  let value = 0;
  for (let index = 0; index < 10_000; index += 1) value = [value];
  assert.throws(() => canonicalJson(value), (error) => error instanceof AuthorizationContractError && error.code === 'AUTHZ_LIMIT_EXCEEDED');
  assert.throws(() => canonicalJson(Array.from({ length: 70 }, () => 'x'.repeat(65_000))), (error) => error.code === 'AUTHZ_LIMIT_EXCEEDED');
  assert.throws(() => canonicalJson({}, { maxBytes: 8 * 1024 * 1024 }), (error) => error.code === 'AUTHZ_INPUT_INVALID');
});

test('canonical parser rejects whitespace, duplicate-key text, oversized strings, and invalid Unicode', () => {
  assert.throws(() => parseCanonicalJson('{"a": 1}'), /canonical/);
  assert.throws(() => parseCanonicalJson('{"a":1,"a":1}'), /canonical/);
  assert.throws(() => canonicalJson('x'.repeat(65_537)), (error) => error.code === 'AUTHZ_LIMIT_EXCEEDED');
  assert.throws(() => canonicalJson('\ud800'), (error) => error.code === 'AUTHZ_INPUT_INVALID');
  assert.throws(() => parseCanonicalJson(Buffer.from([0xc3, 0x28])), (error) => error.code === 'AUTHZ_INPUT_INVALID');
  assert.throws(() => parseCanonicalJson({ toString: () => '{}' }), (error) => error.code === 'AUTHZ_INPUT_INVALID');
});

test('canonical JSON rejects accessors, hidden properties, symbols, and sparse arrays', () => {
  const accessor = {};
  Object.defineProperty(accessor, 'value', { enumerable: true, get() { throw new Error('getter executed'); } });
  assert.throws(() => canonicalJson(accessor), (error) => error instanceof AuthorizationContractError && error.code === 'AUTHZ_INPUT_INVALID');
  const hidden = {};
  Object.defineProperty(hidden, 'value', { enumerable: false, value: 1 });
  assert.throws(() => canonicalJson(hidden), (error) => error.code === 'AUTHZ_INPUT_INVALID');
  assert.throws(() => canonicalJson({ [Symbol('secret')]: 1 }), (error) => error.code === 'AUTHZ_INPUT_INVALID');
  assert.throws(() => canonicalJson(new Array(1)), (error) => error.code === 'AUTHZ_INPUT_INVALID');
  assert.throws(() => canonicalJson(new Proxy({}, { get() { throw new Error('proxy executed'); } })), (error) => error.code === 'AUTHZ_INPUT_INVALID');
});

test('authorization request validator rejects unknown actor and credential assignments', () => {
  const request = {
    schemaVersion: 'ogvcs.authorization/request/v1', requestId: 'hostile',
    actor: { id: 'attacker', class: 'superuser', groups: [], credentialClass: 'forever-token', credentialGeneration: 1, credentialStatus: 'active', authorityEpoch: 1 },
    tenant: 'tenant-alpha', repository: 'game-main', permission: 'discover', reason: null,
    resource: { type: 'repository', path: null, fileId: null, objectId: null, name: 'game-main' },
    context: { reference: null, snapshot: null, policyGeneration: 1, authorityEpoch: 1 },
  };
  assert.throws(() => validateAuthorizationRequest(request), /actor\.class is unknown/);
});

test('authorization paths are canonical relative core paths before policy matching', () => {
  const request = {
    schemaVersion: 'ogvcs.authorization/request/v1', requestId: 'path-check',
    actor: { id: 'caller', class: 'human', groups: [], credentialClass: 'session', credentialGeneration: 1, credentialStatus: 'active', authorityEpoch: 1 },
    tenant: 'tenant-alpha', repository: 'game-main', permission: 'discover', reason: null,
    resource: { type: 'path', path: 'Game/Shared/File.txt', fileId: null, objectId: null, name: null },
    context: { reference: 'main', snapshot: null, policyGeneration: 1, authorityEpoch: 1 },
  };
  assert.doesNotThrow(() => validateAuthorizationRequest(request));
  for (const path of ['/Game/Shared', 'Game//Shared', 'Game/../Restricted', 'Game/./Shared', 'Game/Shared/', `${'a'.repeat(256)}/file`]) {
    assert.throws(() => validateAuthorizationRequest({ ...request, resource: { ...request.resource, path } }), /resource\.path is invalid/);
  }
});

test('grant claim operation and permission are inseparable', () => {
  const claims = {
    schemaVersion: 'ogvcs.authorization/transfer-grant-claims/v1', issuer: 'issuer', keyId: 'key', keyGeneration: 1,
    authorityEpoch: 1, subject: 'subject', tenant: 'tenant', repository: 'repository', permission: 'content.upload',
    operation: 'download', audience: 'cache', issuedAt: 1, expiresAt: 2, nonce: 'nonce', replay: 'single-use',
    objectIds: ['ogvcs:v1:chunk:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'], requestRoot: null,
  };
  assert.throws(() => validateTransferGrantClaims(claims), /operation does not match permission/);
});

test('public threat-vector execution validates kind-specific input before dispatch', async () => {
  const vector = {
    schemaVersion: 'ogvcs.authorization/threat-vector/v1', id: 'hostile-dedup', abuseCase: 'cross-tenant-dedup',
    category: 'deduplication-probe', kind: 'deduplication', input: {},
    expected: { result: 'deny', code: 'DENY_TENANT_BOUNDARY' }, forbiddenResponseFields: ['path'],
  };
  assert.throws(() => validateThreatVector(vector), (error) => error.code === 'AUTHZ_INPUT_INVALID');
  await assert.rejects(() => executeReferenceVector(vector), (error) => error.code === 'AUTHZ_INPUT_INVALID');
});
