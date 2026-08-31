#!/usr/bin/env node
import { createHash, createHmac } from 'node:crypto';
import { readFile, readdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  chunkBytes,
  PROFILE as CHUNKING_PROFILE,
  PRODUCTION_BOUNDARY_VERSION,
  VERIFICATION_RECEIPT_VERIFIER,
} from '@opengamevcs/chunking-manifest';
import { CLAIMS, CONFORMANCE_SECRET_HEX, CONTRACT_VERSION, FAULTS, FIXTURE_BYTES, HOSTILE, IDEMPOTENCY_KEY, PROFILE } from './model.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const check = process.argv.includes('--check');
const canonical = (value) => value === null || typeof value === 'boolean' || typeof value === 'string' || Number.isSafeInteger(value)
  ? JSON.stringify(value) : Array.isArray(value) ? `[${value.map(canonical).join(',')}]`
    : `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
const bytes = (value) => Buffer.from(`${canonical(value)}\n`);
const sha = (value) => createHash('sha256').update(value).digest('hex');
const contentManifestStatementSha256 = (value) => createHash('sha256')
  .update('OGVCS-OBJECT-TRANSFER-CONTENT-MANIFEST-PRODUCTION-V1\0')
  .update(canonical(value))
  .digest('hex');
const u16 = (value) => { const out = Buffer.alloc(2); out.writeUInt16BE(value); return out; };
const objectDigest = createHash('sha256').update('OpenGameVCS object\0').update(u16(1)).update(u16(1)).update(FIXTURE_BYTES).digest('hex');
const objectId = `ogvcs:v1:chunk:sha256:${objectDigest}`;
const secret = Buffer.from(CONFORMANCE_SECRET_HEX, 'hex');
const opaqueKey = createHmac('sha256', secret).update('OGVCS-OBJECT-BACKEND-KEY-V1\0').update(CLAIMS.tenant).update('\0').update(objectId).digest('hex');
const requestRoot = `sha256:${sha(Buffer.concat([Buffer.from('OGVCS-AUTH-REQUEST-ROOT-V1\0'), Buffer.from(canonical([objectId]))]))}`;
const claims = { ...CLAIMS, requestRoot };
const grantBindingSha256 = sha(Buffer.concat([Buffer.from('OGVCS-TRANSFER-GRANT-BINDING-V1\0'), Buffer.from(canonical(claims))]));
const authorityBindingSha256 = sha(Buffer.concat([Buffer.from('OGVCS-TRANSFER-AUTHORITY-BINDING-V1\0'), Buffer.from(canonical({ audience: claims.audience, authorityEpoch: claims.authorityEpoch, issuer: claims.issuer, keyGeneration: claims.keyGeneration, keyId: claims.keyId, objectId, operation: claims.operation, permission: claims.permission, repository: claims.repository, requestRoot: claims.requestRoot, subject: claims.subject, tenant: claims.tenant }))]));
const idempotencyFingerprint = sha(Buffer.concat([Buffer.from('ogvcs.protocol/idempotency/v1\0'), Buffer.from(canonical({ declaredLength: FIXTURE_BYTES.length, objectId, operation: 'start-upload', partSize: 8 }))]));
const sessionId = createHmac('sha256', secret).update('OGVCS-UPLOAD-SESSION-ID-V1\0').update(opaqueKey).update('\0').update(IDEMPOTENCY_KEY).digest('hex');
const contentManifestFixtureBytes = Buffer.from('OpenGameVCS object-transfer content-manifest fixture\n', 'utf8');
const contentManifestFixture = await chunkBytes(contentManifestFixtureBytes);
const chunkingProfileText = `${CHUNKING_PROFILE.namespace}/${CHUNKING_PROFILE.id}@${CHUNKING_PROFILE.major}`;
const contentManifestObjectId = contentManifestFixture.manifest.objectId;
const contentManifestVerificationReceiptSha256 = contentManifestStatementSha256({
  boundary: PRODUCTION_BOUNDARY_VERSION,
  logicalBytes: String(contentManifestFixtureBytes.length),
  manifestObjectId: contentManifestObjectId,
  manifestSha256: sha(contentManifestFixture.manifest.bytes),
  profile: chunkingProfileText,
  verifier: VERIFICATION_RECEIPT_VERIFIER,
  wholeFileSha256: sha(contentManifestFixtureBytes),
});
const parts = [];
for (let offset = 0, index = 0; offset < FIXTURE_BYTES.length; offset += 8, index += 1) {
  const part = FIXTURE_BYTES.subarray(offset, offset + 8);
  parts.push({ index, length: part.length, sha256: sha(part), bytesHex: part.toString('hex') });
}
const backend = { schemaVersion: 'ogvcs.object-transfer/backend-vectors/v1', cases: [
  { id: 'create-if-absent', input: { tenant: CLAIMS.tenant, objectId, bytesHex: FIXTURE_BYTES.toString('hex') }, expected: { createdFirst: true, createdSecond: false, length: FIXTURE_BYTES.length, opaqueKey, payloadSha256: sha(FIXTURE_BYTES), validatorTag: `sha256-${sha(FIXTURE_BYTES)}` } },
  { id: 'half-open-range', input: { objectId, start: 4, endExclusive: 17 }, expected: { bytesHex: FIXTURE_BYTES.subarray(4, 17).toString('hex'), contentSha256: sha(FIXTURE_BYTES.subarray(4, 17)), length: 13, totalLength: FIXTURE_BYTES.length } },
  { id: 'safe-delete-receipt', input: { objectId, opaqueKey }, expected: { rawCallerCode: 'TRANSFER_LIFECYCLE_STALE', requiresAuthoritativeOneUsePermit: true, responseLossReplay: true } },
], 'x-ogvcs-license': 'MIT' };
const lifecycle = { schemaVersion: 'ogvcs.object-transfer/lifecycle-vectors/v1', cases: [
  { id: 'complete-state-chain', input: { initialGeneration: 1 }, expected: { states: ['staged', 'available', 'quarantined', 'available', 'quarantined', 'deleting', 'deleted'], generations: [1, 2, 3, 4, 5, 6, 7] } },
  { id: 'disallowed-shortcuts', input: { transitions: [['staged', 'deleted'], ['available', 'deleting'], ['deleting', 'available']] }, expected: { code: 'TRANSFER_LIFECYCLE_STALE', transitionCount: 0 } },
], 'x-ogvcs-license': 'MIT' };
const resume = { schemaVersion: 'ogvcs.object-transfer/resume-vectors/v1', cases: [
  { id: 'multipart-resume', input: { objectId, declaredLength: FIXTURE_BYTES.length, partSize: 8, parts, replayPartOrder: [0, 2, 1, 2, 3, 4] }, expected: { authorityBindingSha256, grantBindingSha256, idempotencyFingerprint, opaqueKey, receivedIndexes: parts.map(({ index }) => index), requestRoot, sessionId } },
  { id: 'receipt-loss-retry', input: { loseResponseAfterAvailable: true, sessionId }, expected: { backendCreates: 1, lifecycleGeneration: 2, lifecycleState: 'available', stableReplay: true } },
], 'x-ogvcs-license': 'MIT' };
const transactionParticipant = { schemaVersion: 'ogvcs.object-transfer/transaction-participant-vectors/v1', cases: [
  { id: 'submit-consume-publication', input: { capability: 'submit.consume-publication', method: 'consumePublication', objects: [
    { opaqueKey: 'a'.repeat(64), objectId: `ogvcs:v1:chunk:sha256:${'1'.repeat(64)}`, expectedState: 'available', expectedGeneration: 2, expectedHealth: 'healthy', expectedHealthGeneration: 3, authorityBindingSha256: 'b'.repeat(64), backendReceiptSha256: 'c'.repeat(64), verificationReceiptSha256: null, deletionReceiptSha256: null },
    { opaqueKey: 'f'.repeat(64), objectId: contentManifestObjectId, expectedState: 'quarantined', expectedGeneration: 7, expectedHealth: 'healthy', expectedHealthGeneration: 8, authorityBindingSha256: 'b'.repeat(64), backendReceiptSha256: 'c'.repeat(64), verificationReceiptSha256: contentManifestVerificationReceiptSha256, deletionReceiptSha256: null },
  ] }, expected: { objects: [
    { priorState: 'available', nextState: 'available', nextGeneration: 2, reachabilityRecorded: true },
    { priorState: 'quarantined', nextState: 'available', nextGeneration: 8, reachabilityRecorded: true },
  ] } },
  { id: 'gc-acquire-deleting', input: { capability: 'gc.acquire-deleting', method: 'acquireDeleting', objects: [
    { opaqueKey: 'a'.repeat(64), objectId: `ogvcs:v1:chunk:sha256:${'1'.repeat(64)}`, expectedState: 'quarantined', expectedGeneration: 2, expectedHealth: 'healthy', expectedHealthGeneration: 3, authorityBindingSha256: 'b'.repeat(64), backendReceiptSha256: 'c'.repeat(64), verificationReceiptSha256: null, deletionReceiptSha256: null },
  ] }, expected: { objects: [{ priorState: 'quarantined', nextState: 'deleting', nextGeneration: 3, reachabilityRecorded: false }] } },
  { id: 'gc-complete-deletion', input: { capability: 'gc.complete-deletion', method: 'completeDeletion', objects: [
    { opaqueKey: 'a'.repeat(64), objectId: `ogvcs:v1:chunk:sha256:${'1'.repeat(64)}`, expectedState: 'deleting', expectedGeneration: 2, expectedHealth: 'not-applicable', expectedHealthGeneration: null, authorityBindingSha256: 'b'.repeat(64), backendReceiptSha256: 'c'.repeat(64), verificationReceiptSha256: null, deletionReceiptSha256: '9'.repeat(64) },
  ] }, expected: { objects: [{ priorState: 'deleting', nextState: 'deleted', nextGeneration: 3, reachabilityRecorded: false }] } },
  { id: 'transfer-reverify-deleted', input: { capability: 'transfer.reverify-deleted', method: 'reverifyDeleted', objects: [
    { opaqueKey: 'a'.repeat(64), objectId: `ogvcs:v1:chunk:sha256:${'1'.repeat(64)}`, expectedState: 'deleted', expectedGeneration: 2, expectedHealth: 'not-applicable', expectedHealthGeneration: null, authorityBindingSha256: 'b'.repeat(64), backendReceiptSha256: null, verificationReceiptSha256: '8'.repeat(64), deletionReceiptSha256: '9'.repeat(64) },
  ] }, expected: { objects: [{ priorState: 'deleted', nextState: 'staged', nextGeneration: 3, reachabilityRecorded: false }] } },
  { id: 'transfer-record-available', input: { capability: 'transfer.record-available', method: 'recordAvailable', objects: [
    { opaqueKey: 'a'.repeat(64), objectId: contentManifestObjectId, expectedState: 'staged', expectedGeneration: 2, expectedHealth: 'not-applicable', expectedHealthGeneration: null, authorityBindingSha256: 'b'.repeat(64), backendReceiptSha256: 'c'.repeat(64), verificationReceiptSha256: contentManifestVerificationReceiptSha256, deletionReceiptSha256: null },
  ] }, expected: { objects: [{ priorState: 'staged', nextState: 'available', nextGeneration: 3, reachabilityRecorded: false }] } },
], 'x-ogvcs-license': 'MIT' };
const hostile = { schemaVersion: 'ogvcs.object-transfer/hostile-vectors/v1', cases: HOSTILE, 'x-ogvcs-license': 'MIT' };
const faults = { schemaVersion: 'ogvcs.object-transfer/fault-vectors/v1', cases: FAULTS, 'x-ogvcs-license': 'MIT' };
const backendCapabilities = { schemaVersion: 'ogvcs.object-transfer/backend-capabilities-vectors/v1', cases: [
  { id: 'filesystem-capability-profile', input: { backendKind: 'filesystem' }, expected: { profile: 'storage.opengamevcs/filesystem@1', objectBytesMaximum: 67108864, rangeBytesMaximum: 8388608, createIfAbsent: true, exactMetadata: true, wholeObjectVerification: true, verifiedRanges: true, boundedPrefixList: true, generationFencedDelete: true, multipartEtagIsDigest: false } },
  { id: 's3-compatible-capability-profile', input: { backendKind: 's3-compatible' }, expected: { profile: 'storage.opengamevcs/s3-compatible@1', objectBytesMaximum: 67108864, rangeBytesMaximum: 8388608, createIfAbsent: true, exactMetadata: true, wholeObjectVerification: true, verifiedRanges: true, boundedPrefixList: true, generationFencedDelete: true, multipartEtagIsDigest: false } },
  { id: 'structural-forgery', input: { matchingMethodNames: true, explicitTrustedConstruction: false }, expected: { code: 'TRANSFER_INPUT_INVALID', dispatched: false } },
], 'x-ogvcs-license': 'MIT' };
const s3Backend = { schemaVersion: 'ogvcs.object-transfer/s3-backend-vectors/v1', cases: [
  { id: 'aws-sigv4-list-objects', input: { url: 'https://examplebucket.s3.amazonaws.com/?max-keys=2&prefix=J', method: 'GET', accessKeyId: 'AKIAIOSFODNN7EXAMPLE', region: 'us-east-1', date: '20130524T000000Z', payloadSha256: sha(Buffer.alloc(0)) }, expected: { canonicalRequestSha256: 'df57d21db20da04d7fa30298dd4488ba3a2b47ca3a489c74750e0f1e7df1b9b7', signature: '34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7' } },
  { id: 'acknowledgement-before-durability', input: { conditionalPutStatus: 200, corruptReadBack: true }, expected: { code: 'TRANSFER_BACKEND_CORRUPT', durableReceipt: false, lifecycleMutation: false } },
  { id: 'response-loss-conditional-replay', input: { conditionalHeader: 'If-None-Match:*', loseFirstResponse: true }, expected: { backendObjects: 1, readBackRequired: true, stableReceipt: true } },
  { id: 'multipart-etag-is-opaque', input: { etag: '9b74c9897bac770ffc029102a200c5de-2' }, expected: { contentDigestAccepted: false, conditionalTokenAccepted: true } },
  { id: 'sharded-prefix-list', input: { opaquePrefix: 'abcdef', maximum: 1 }, expected: { storagePrefix: 'objects/ab/cd/abcdef', pageAndResultBound: 2, validatesFullShaAndShards: true } },
], 'x-ogvcs-license': 'MIT' };
const contentTransfer = { schemaVersion: 'ogvcs.object-transfer/content-transfer-vectors/v1', cases: [
  { id: 'exact-logical-100-gib', input: { logicalLength: 107374182400, canonicalChunkLength: 67108864 }, expected: { chunkCount: 1600, pageCount: 7, descriptorsPerPageMaximum: 256, allocationMaximum: 67108864 } },
  { id: 'interrupted-ledger-resume', input: { verifiedIndexes: [0, 1, 3], requestedPage: 0 }, expected: { pendingIndexes: [2, 4], retransmitVerified: false, durableCursor: true } },
  { id: 'logical-size-plus-one', input: { logicalLength: 107374182401 }, expected: { code: 'TRANSFER_INPUT_INVALID', planPublished: false } },
  { id: 'chunk-count-plus-one', input: { chunkCount: 100001 }, expected: { code: 'TRANSFER_LIMIT_EXCEEDED', planPublished: false } },
], 'x-ogvcs-license': 'MIT' };
const batch = { schemaVersion: 'ogvcs.object-transfer/batch-vectors/v1', cases: [
  { id: 'exact-plan-binding', input: { objectCount: 3, requestedRange: [4, 17] }, expected: { bindsGrant: true, bindsObjectSet: true, bindsRequestRoot: true, halfOpenRange: true, packOffsets: [0, 35, 70] } },
  { id: 'tampered-plan', input: { mutation: 'items[1].packOffset' }, expected: { code: 'TRANSFER_AUTHORIZATION_DENIED', returnedBytes: 0 } },
  { id: 'duplicate-object', input: { duplicateIndex: 1 }, expected: { code: 'TRANSFER_INPUT_INVALID', existenceChecks: 0 } },
  { id: 'batch-count-plus-one', input: { objectCount: 4097 }, expected: { code: 'TRANSFER_INPUT_INVALID', existenceChecks: 0 } },
  { id: 'hidden-denial-position', input: { deniedPositions: ['early', 'middle', 'last'] }, expected: { code: 'TRANSFER_AUTHORIZATION_DENIED', partialPlan: false, hiddenCountDisclosed: false } },
], 'x-ogvcs-license': 'MIT' };
const operations = { schemaVersion: 'ogvcs.object-transfer/operations-vectors/v1', cases: [
  { id: 'durable-unique-quota-replay', input: { reserveResponseLost: true, uniqueBytes: 7, limit: 10 }, expected: { retryReservedBytes: 7, doubleCharged: false, releaseIdempotent: true } },
  { id: 'quota-dimensions', input: {}, expected: { dimensions: ['staging-bytes', 'durable-unique-bytes', 'request-rate', 'transfer-bytes'] } },
  { id: 'privacy-safe-telemetry', input: { requestedLabels: ['operation', 'backend', 'outcome', 'quota', 'integrity'] }, expected: { objectIdLabel: false, backendKeyLabel: false, pathLabel: false, credentialLabel: false, boundedCardinality: true } },
  { id: 'integrity-event-redaction', input: { event: 'integrity-failure' }, expected: { includesTenantScopeDigest: true, includesOperation: true, includesObjectId: false, includesPath: false } },
  { id: 'safe-error-classification', input: { codes: ['TRANSFER_AUTHORIZATION_DENIED', 'TRANSFER_BACKEND_CONFLICT', 'TRANSFER_BACKEND_CORRUPT', 'TRANSFER_BACKEND_IO', 'TRANSFER_LIMIT_EXCEEDED'] }, expected: { broadMessagesContainObjectIdentity: false, credentialRedaction: true, retryOnlyUnavailableOrExplicitConflict: true } },
], 'x-ogvcs-license': 'MIT' };
async function output(path, value) { const expected = bytes(value); const absolute = resolve(ROOT, path); if (check) { const actual = await readFile(absolute).catch(() => null); if (!actual?.equals(expected)) throw new Error(`${path} is stale`); } else await writeFile(absolute, expected); }
await output('vectors/backend.json', backend); await output('vectors/lifecycle.json', lifecycle); await output('vectors/resume.json', resume); await output('vectors/transaction-participant.json', transactionParticipant); await output('vectors/hostile.json', hostile); await output('vectors/faults.json', faults); await output('vectors/backend-capabilities.json', backendCapabilities); await output('vectors/s3-backend.json', s3Backend); await output('vectors/content-transfer.json', contentTransfer); await output('vectors/batch.json', batch); await output('vectors/operations.json', operations);
async function files(directory) { const result = []; for (const entry of await readdir(resolve(ROOT, directory), { withFileTypes: true })) { const path = `${directory}/${entry.name}`; if (entry.isDirectory()) result.push(...await files(path)); else result.push(path); } return result; }
const shipped = ['LICENSE', 'README.md', 'package.json', 'validate-spec.mjs', ...await files('docs'), ...await files('profiles'), ...await files('registries'), ...await files('schemas'), ...await files('scripts'), ...await files('test'), ...await files('vectors')].filter((path) => path !== 'manifest.json').sort();
const artifacts = [];
for (const path of shipped) { const body = await readFile(resolve(ROOT, path)); artifacts.push({ bytes: body.length, path, sha256: sha(body) }); }
const artifactSetSha256 = sha(Buffer.concat(artifacts.map((item) => Buffer.from(`${item.path}\0${item.sha256}\0${item.bytes}\n`))));
await output('manifest.json', { schemaVersion: 'ogvcs.object-transfer/contract-manifest/v1', contractVersion: CONTRACT_VERSION, profile: PROFILE, profiles: [PROFILE, 'storage.opengamevcs/s3-compatible@1', 'storage.opengamevcs/content-transfer@1'], predecessorContracts: { authorization: '1.0.0', chunking: '0.1.0-rc.1', protocol: '1.0.0-rc.1', repositoryFormat: 1 }, artifactSetSha256, artifacts, counts: { artifacts: artifacts.length, backendCases: backend.cases.length, backendCapabilityCases: backendCapabilities.cases.length, batchCases: batch.cases.length, contentTransferCases: contentTransfer.cases.length, faultCases: faults.cases.length, hostileCases: hostile.cases.length, lifecycleCases: lifecycle.cases.length, operationCases: operations.cases.length, resumeCases: resume.cases.length, s3BackendCases: s3Backend.cases.length, schemas: 16, transactionCases: transactionParticipant.cases.length }, generatedBy: { generatorSha256: sha(await readFile(fileURLToPath(import.meta.url))), modelSha256: sha(await readFile(resolve(ROOT, 'scripts/model.mjs'))) }, license: 'MIT' });
if (!check) process.stdout.write(`${resolve(ROOT, 'manifest.json')}\n`);
