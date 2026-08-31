#!/usr/bin/env node
import { createHash, createHmac } from 'node:crypto';
import { lstat, readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(process.env.OGVCS_OBJECT_TRANSFER_CONTRACT_ROOT ?? dirname(fileURLToPath(import.meta.url)));
const canonical = (value) => value === null || typeof value === 'boolean' || typeof value === 'string' || Number.isSafeInteger(value)
  ? JSON.stringify(value) : Array.isArray(value) ? `[${value.map(canonical).join(',')}]`
    : value && typeof value === 'object' ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}` : fail('noncanonical value');
const sha = (value) => createHash('sha256').update(value).digest('hex');
function fail(message) { throw new Error(`object-transfer-contract-v1: ${message}`); }
async function load(path) { const absolute = resolve(ROOT, path); const stat = await lstat(absolute).catch(() => null); if (!stat?.isFile() || stat.isSymbolicLink() || stat.size > 16 * 1024 * 1024) fail(`${path} is not a bounded regular file`); const body = await readFile(absolute); let value; try { value = JSON.parse(body); } catch { fail(`${path} is invalid JSON`); } if (!body.equals(Buffer.from(`${canonical(value)}\n`))) fail(`${path} is not canonical JSON`); return { body, value }; }
const CONTRACT_VERSION = '0.1.0-rc.6';
const CONTENT_MANIFEST_OBJECT_ID = 'ogvcs:v1:content-manifest:sha256:9b1db952c6d3fbc9125dda4dfef73b5e83ec9bbe466329fb31c9d834ca8c20c3';
const CONTENT_MANIFEST_PRODUCTION_RECEIPT_SHA256 = 'e43f9cc933dc0c2da2a963acb4a54b20dba0e62f31fd9c63f33afb98b60a0963';
const profile = (await load('profiles/filesystem-v1.json')).value;
if (profile.profile !== 'storage.opengamevcs/filesystem@1' || profile.candidateState !== 'development-not-production-write-eligible' || profile.backendKey.algorithm !== 'HMAC-SHA-256' || profile.backendKey.domainAscii !== 'OGVCS-OBJECT-BACKEND-KEY-V1' || profile.backendKey.domainNulTerminated !== true || profile.containment.directoryIdentityPinned !== true || profile.containment.finalComponentNoFollow !== true || profile.containment.sameAuthorityConcurrentAncestorMutation !== 'requires-native-directory-handle-relative-adapter' || profile.durability.create !== 'file-sync+atomic-link-no-replace+directory-sync-on-create-or-eexist' || profile.durability.delete !== 'authoritative-one-use-permit+durable-intent+generation-bound-unlink+directory-sync' || profile.durability.windowsDirectorySync !== 'suppress-only-EPERM-after-verified-directory-open' || profile.locking.commitFence !== 'current-token-before-and-after-persisted-commit' || profile.locking.lease !== 'renewed-while-operation-live' || profile.locking.takeover !== 'rename+post-rename-renewal-recheck' || profile.grantAuthority.clock !== 'service-owned' || profile.grantAuthority.singleUseReplay !== 'persistent-atomic-exclusive-claim' || profile.limits.objectBytesMaximum !== 67108864 || profile.limits.partBytesMaximum !== 4194304 || profile.limits.rangeBytesMaximum !== 8388608 || profile.limits.sessionsPerTenantMaximum !== 256 || profile.limits.nonceRecordsMaximum !== 4096 || profile.limits.lifecycleRecordsMaximum !== 4096 || profile.limits.deleteIntentsMaximum !== 4096 || profile.limits.workingMemoryBytesMaximum !== 268435456) fail('filesystem profile constants are invalid');
const s3Profile = (await load('profiles/s3-compatible-v1.json')).value;
if (s3Profile.profile !== 'storage.opengamevcs/s3-compatible@1'
    || s3Profile.authentication.algorithm !== 'AWS4-HMAC-SHA256'
    || s3Profile.authentication.canonicalQueryOrder !== 'percent-encoded-code-unit-order'
    || s3Profile.authentication.credentialRedaction !== true
    || s3Profile.durability.acknowledgement !== 'insufficient-without-exact-read-back'
    || s3Profile.durability.etag !== 'opaque-cas-token-not-content-digest'
    || s3Profile.durability.range !== 'whole-object-verified-before-bounded-range-release'
    || s3Profile.keyspace.callerObjectIdInKey !== false || s3Profile.keyspace.tenantScopedHmac !== true
    || s3Profile.limits.objectBytesMaximum !== 67108864 || s3Profile.limits.rangeBytesMaximum !== 8388608
    || s3Profile.limits.listMaximum !== 4096 || s3Profile.limits.retriesMaximum !== 4
    || s3Profile.transport.httpsRequired !== true
    || s3Profile.transport.loopbackHttpRequiresExplicitTestOptIn !== true) fail('S3-compatible profile constants are invalid');
const contentProfile = (await load('profiles/content-transfer-v1.json')).value;
if (contentProfile.profile !== 'storage.opengamevcs/content-transfer@1'
    || contentProfile.limits.logicalBytesMaximum !== 107374182400
    || contentProfile.limits.canonicalObjectBytesMaximum !== 67108864
    || contentProfile.limits.chunksMaximum !== 100000
    || contentProfile.limits.descriptorsPerPageMaximum !== 256
    || contentProfile.limits.pagesMaximum !== 391
    || contentProfile.limits.plansMaximum !== 4096
    || canonical(contentProfile.quotaDimensions) !== canonical(['staging-bytes', 'durable-unique-bytes', 'request-rate', 'transfer-bytes'])
    || contentProfile.resume.retransmitVerifiedParts !== false
    || contentProfile.resume.wholeFileVerificationRequired !== true
    || contentProfile.telemetry.objectIdentityLabelsAllowed !== false) fail('content-transfer profile constants are invalid');
const transitions = (await load('registries/transitions.json')).value.entries.map(({ from, to }) => `${from}->${to}`);
if (canonical(transitions) !== canonical(['available->quarantined', 'deleting->deleted', 'quarantined->available', 'quarantined->deleting', 'staged->available'])) fail('lifecycle transitions are invalid');
const backend = (await load('vectors/backend.json')).value; const resume = (await load('vectors/resume.json')).value;
const fixture = Buffer.from(backend.cases[0].input.bytesHex, 'hex'); const u16 = (value) => { const out = Buffer.alloc(2); out.writeUInt16BE(value); return out; };
const digest = createHash('sha256').update('OpenGameVCS object\0').update(u16(1)).update(u16(1)).update(fixture).digest('hex');
const objectId = `ogvcs:v1:chunk:sha256:${digest}`; if (objectId !== backend.cases[0].input.objectId) fail('fixture ObjectID differs from OGVCS-002 preimage');
const expectedKey = createHmac('sha256', Buffer.from('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', 'hex')).update('OGVCS-OBJECT-BACKEND-KEY-V1\0').update('tenant-alpha').update('\0').update(objectId).digest('hex');
if (backend.cases[0].expected.opaqueKey !== expectedKey || resume.cases[0].expected.opaqueKey !== expectedKey) fail('opaque backend key derivation differs');
for (const [name, schemaVersion, minimum] of [
  ['backend', 'ogvcs.object-transfer/backend-vectors/v1', 2],
  ['backend-capabilities', 'ogvcs.object-transfer/backend-capabilities-vectors/v1', 3],
  ['batch', 'ogvcs.object-transfer/batch-vectors/v1', 5],
  ['content-transfer', 'ogvcs.object-transfer/content-transfer-vectors/v1', 4],
  ['faults', 'ogvcs.object-transfer/fault-vectors/v1', 2],
  ['hostile', 'ogvcs.object-transfer/hostile-vectors/v1', 2],
  ['lifecycle', 'ogvcs.object-transfer/lifecycle-vectors/v1', 2],
  ['operations', 'ogvcs.object-transfer/operations-vectors/v1', 5],
  ['resume', 'ogvcs.object-transfer/resume-vectors/v1', 2],
  ['s3-backend', 'ogvcs.object-transfer/s3-backend-vectors/v1', 5],
  ['transaction-participant', 'ogvcs.object-transfer/transaction-participant-vectors/v1', 5],
]) {
  const value = (await load(`vectors/${name}.json`)).value;
  if (value.schemaVersion !== schemaVersion || value.cases.length < minimum
      || new Set(value.cases.map(({ id }) => id)).size !== value.cases.length) fail(`${name} vector set is invalid`);
}
const transactionVectors = (await load('vectors/transaction-participant.json')).value;
if (canonical(transactionVectors.cases.map(({ id, input, expected }) => ({
  id,
  capability: input.capability,
  method: input.method,
  objects: input.objects.length,
  objectIds: input.objects.map(({ objectId }) => objectId),
  verificationReceipts: input.objects.map(({ verificationReceiptSha256 }) => verificationReceiptSha256),
  next: expected.objects.map(({ nextGeneration, nextState, priorState, reachabilityRecorded }) => ({
    priorState, nextState, nextGeneration, reachabilityRecorded,
  })),
}))) !== canonical([
  { id: 'submit-consume-publication', capability: 'submit.consume-publication', method: 'consumePublication', objects: 2, objectIds: [`ogvcs:v1:chunk:sha256:${'1'.repeat(64)}`, CONTENT_MANIFEST_OBJECT_ID], verificationReceipts: [null, CONTENT_MANIFEST_PRODUCTION_RECEIPT_SHA256], next: [{ priorState: 'available', nextState: 'available', nextGeneration: 2, reachabilityRecorded: true }, { priorState: 'quarantined', nextState: 'available', nextGeneration: 8, reachabilityRecorded: true }] },
  { id: 'gc-acquire-deleting', capability: 'gc.acquire-deleting', method: 'acquireDeleting', objects: 1, objectIds: [`ogvcs:v1:chunk:sha256:${'1'.repeat(64)}`], verificationReceipts: [null], next: [{ priorState: 'quarantined', nextState: 'deleting', nextGeneration: 3, reachabilityRecorded: false }] },
  { id: 'gc-complete-deletion', capability: 'gc.complete-deletion', method: 'completeDeletion', objects: 1, objectIds: [`ogvcs:v1:chunk:sha256:${'1'.repeat(64)}`], verificationReceipts: [null], next: [{ priorState: 'deleting', nextState: 'deleted', nextGeneration: 3, reachabilityRecorded: false }] },
  { id: 'transfer-reverify-deleted', capability: 'transfer.reverify-deleted', method: 'reverifyDeleted', objects: 1, objectIds: [`ogvcs:v1:chunk:sha256:${'1'.repeat(64)}`], verificationReceipts: ['8'.repeat(64)], next: [{ priorState: 'deleted', nextState: 'staged', nextGeneration: 3, reachabilityRecorded: false }] },
  { id: 'transfer-record-available', capability: 'transfer.record-available', method: 'recordAvailable', objects: 1, objectIds: [CONTENT_MANIFEST_OBJECT_ID], verificationReceipts: [CONTENT_MANIFEST_PRODUCTION_RECEIPT_SHA256], next: [{ priorState: 'staged', nextState: 'available', nextGeneration: 3, reachabilityRecorded: false }] },
])) fail('transaction participant vectors are not exact');
const capabilityVectors = (await load('vectors/backend-capabilities.json')).value;
if (canonical(capabilityVectors.cases.map(({ id, expected }) => ({ id, expected }))) !== canonical([
  { id: 'filesystem-capability-profile', expected: { profile: 'storage.opengamevcs/filesystem@1', objectBytesMaximum: 67108864, rangeBytesMaximum: 8388608, createIfAbsent: true, exactMetadata: true, wholeObjectVerification: true, verifiedRanges: true, boundedPrefixList: true, generationFencedDelete: true, multipartEtagIsDigest: false } },
  { id: 's3-compatible-capability-profile', expected: { profile: 'storage.opengamevcs/s3-compatible@1', objectBytesMaximum: 67108864, rangeBytesMaximum: 8388608, createIfAbsent: true, exactMetadata: true, wholeObjectVerification: true, verifiedRanges: true, boundedPrefixList: true, generationFencedDelete: true, multipartEtagIsDigest: false } },
  { id: 'structural-forgery', expected: { code: 'TRANSFER_INPUT_INVALID', dispatched: false } },
])) fail('backend capability vectors are not exact');
const s3Vectors = (await load('vectors/s3-backend.json')).value;
const aws = s3Vectors.cases.find(({ id }) => id === 'aws-sigv4-list-objects');
const emptySha256 = sha(Buffer.alloc(0));
const canonicalRequest = `GET\n/\nmax-keys=2&prefix=J\nhost:examplebucket.s3.amazonaws.com\nx-amz-content-sha256:${emptySha256}\nx-amz-date:20130524T000000Z\n\nhost;x-amz-content-sha256;x-amz-date\n${emptySha256}`;
const canonicalRequestSha256 = sha(canonicalRequest);
const hmac = (key, value) => createHmac('sha256', key).update(value).digest();
const signingKey = hmac(hmac(hmac(hmac('AWS4wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', '20130524'), 'us-east-1'), 's3'), 'aws4_request');
const signature = createHmac('sha256', signingKey).update(`AWS4-HMAC-SHA256\n20130524T000000Z\n20130524/us-east-1/s3/aws4_request\n${canonicalRequestSha256}`).digest('hex');
if (aws?.expected.canonicalRequestSha256 !== canonicalRequestSha256 || canonicalRequestSha256 !== 'df57d21db20da04d7fa30298dd4488ba3a2b47ca3a489c74750e0f1e7df1b9b7'
    || aws?.expected.signature !== signature || signature !== '34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7'
    || s3Vectors.cases.find(({ id }) => id === 'acknowledgement-before-durability')?.expected.lifecycleMutation !== false
    || s3Vectors.cases.find(({ id }) => id === 'multipart-etag-is-opaque')?.expected.contentDigestAccepted !== false) fail('S3 backend vectors are not exact');
const contentVectors = (await load('vectors/content-transfer.json')).value;
const exactScale = contentVectors.cases.find(({ id }) => id === 'exact-logical-100-gib');
if (exactScale?.input.logicalLength !== exactScale?.input.canonicalChunkLength * exactScale?.expected.chunkCount
    || exactScale?.expected.chunkCount !== 1600 || exactScale?.expected.pageCount !== 7
    || Math.ceil(exactScale.expected.chunkCount / exactScale.expected.descriptorsPerPageMaximum) !== exactScale.expected.pageCount
    || contentVectors.cases.find(({ id }) => id === 'logical-size-plus-one')?.input.logicalLength !== 107374182401) fail('content-transfer vectors are not exact');
const batchVectors = (await load('vectors/batch.json')).value;
if (batchVectors.cases.find(({ id }) => id === 'batch-count-plus-one')?.input.objectCount !== 4097
    || batchVectors.cases.find(({ id }) => id === 'hidden-denial-position')?.expected.partialPlan !== false
    || batchVectors.cases.find(({ id }) => id === 'tampered-plan')?.expected.returnedBytes !== 0) fail('batch vectors are not exact');
const operationVectors = (await load('vectors/operations.json')).value;
if (operationVectors.cases.find(({ id }) => id === 'privacy-safe-telemetry')?.expected.objectIdLabel !== false
    || operationVectors.cases.find(({ id }) => id === 'integrity-event-redaction')?.expected.includesObjectId !== false
    || operationVectors.cases.find(({ id }) => id === 'durable-unique-quota-replay')?.expected.doubleCharged !== false) fail('operation/error vectors are not exact');
const lifecycleSchema = (await load('schemas/lifecycle-record.schema.json')).value; const sessionSchema = (await load('schemas/session-record.schema.json')).value; const lockSchema = (await load('schemas/lock-owner.schema.json')).value; const nonceSchema = (await load('schemas/nonce-claim.schema.json')).value; const deleteIntentSchema = (await load('schemas/delete-intent.schema.json')).value; const fenceSchema = (await load('schemas/backend-lifecycle-fence.schema.json')).value; const transactionContextSchema = (await load('schemas/lifecycle-transaction-context.schema.json')).value; const transactionResultSchema = (await load('schemas/lifecycle-transaction-adapter-result.schema.json')).value; const backendCapabilitiesSchema = (await load('schemas/backend-capabilities.schema.json')).value; const batchPlanSchema = (await load('schemas/batch-download-plan.schema.json')).value; const contentPlanSchema = (await load('schemas/content-transfer-plan.schema.json')).value; const quotaSchema = (await load('schemas/durable-quota-entry.schema.json')).value; const internalEventSchema = (await load('schemas/internal-event.schema.json')).value; const lifecycleAdapterSchema = (await load('schemas/lifecycle-adapter-capabilities.schema.json')).value; const telemetrySchema = (await load('schemas/telemetry-observation.schema.json')).value; await load('schemas/vector-set.schema.json');
if (!lifecycleSchema.required.includes('tenantScopeSha256') || !lifecycleSchema.required.includes('deletionReceiptSha256') || !Array.isArray(lifecycleSchema.allOf)
    || !sessionSchema.required.includes('tenantScopeSha256') || !sessionSchema.required.includes('cleanupAfterUnixMs')
    || !sessionSchema.required.includes('updatedAtUnixMs') || !Array.isArray(sessionSchema.allOf)
    || lockSchema.additionalProperties !== false || nonceSchema.additionalProperties !== false
    || deleteIntentSchema.additionalProperties !== false || !deleteIntentSchema.required.includes('expectedGeneration')
    || fenceSchema.additionalProperties !== false || !fenceSchema.required.includes('deletions')
    || transactionContextSchema.additionalProperties !== false || !transactionContextSchema.required.includes('capability')
    || !transactionContextSchema.required.includes('objects')
    || transactionContextSchema.properties.lifecycleContractVersion?.const !== CONTRACT_VERSION
    || transactionResultSchema.additionalProperties !== false || !transactionResultSchema.required.includes('persistedFacts')
    || !transactionResultSchema.properties.capability?.enum?.includes('transfer.reverify-deleted')
    || backendCapabilitiesSchema.properties.multipartEtagIsDigest?.const !== false
    || backendCapabilitiesSchema.properties.objectBytesMaximum?.maximum !== 67108864
    || batchPlanSchema.properties.items?.maxItems !== 4096
    || batchPlanSchema.properties.totalBytes?.maximum !== 107374182400
    || contentPlanSchema.properties.logicalLength?.maximum !== 107374182400
    || contentPlanSchema.properties.pages?.maxItems !== 391
    || quotaSchema.properties.state?.enum?.length !== 3
    || internalEventSchema.oneOf?.length !== 2
    || lifecycleAdapterSchema.properties.storageAuthority?.enum?.includes('repository-metadata') !== true
    || telemetrySchema.additionalProperties !== false
    || Object.hasOwn(telemetrySchema.properties, 'objectId')) fail('persisted-state schemas omit hardened fields');
const manifest = (await load('manifest.json')).value;
if (manifest.contractVersion !== CONTRACT_VERSION || manifest.profile !== profile.profile
    || canonical(manifest.profiles) !== canonical([profile.profile, s3Profile.profile, contentProfile.profile])
    || manifest.predecessorContracts.authorization !== '1.0.0' || manifest.predecessorContracts.protocol !== '1.0.0-rc.1') fail('manifest header is invalid');
if (new Set(manifest.artifacts.map(({ path }) => path)).size !== manifest.artifacts.length || manifest.artifacts.some(({ path }, index) => !/^[A-Za-z0-9._/-]+$/u.test(path) || path.startsWith('/') || path.split('/').includes('..') || index > 0 && manifest.artifacts[index - 1].path >= path)) fail('artifact inventory is unsafe');
for (const artifact of manifest.artifacts) { const body = await readFile(resolve(ROOT, artifact.path)); if (body.length !== artifact.bytes || sha(body) !== artifact.sha256) fail(`${artifact.path} differs from manifest`); if (artifact.path.endsWith('.json') && artifact.path !== 'package.json') await load(artifact.path); }
const artifactSetSha256 = sha(Buffer.concat(manifest.artifacts.map((item) => Buffer.from(`${item.path}\0${item.sha256}\0${item.bytes}\n`))));
if (artifactSetSha256 !== manifest.artifactSetSha256 || manifest.counts.artifacts !== manifest.artifacts.length
    || manifest.counts.backendCases !== 3 || manifest.counts.backendCapabilityCases !== 3
    || manifest.counts.batchCases !== 5 || manifest.counts.contentTransferCases !== 4
    || manifest.counts.faultCases !== 9 || manifest.counts.hostileCases !== 19
    || manifest.counts.lifecycleCases !== 2 || manifest.counts.operationCases !== 5
    || manifest.counts.resumeCases !== 2 || manifest.counts.s3BackendCases !== 5
    || manifest.counts.schemas !== 16 || manifest.counts.transactionCases !== 5) fail('manifest counts or digest differ');
process.stdout.write(`${canonical({ artifactSetSha256, objectId, opaqueKey: expectedKey, profile: profile.profile })}\n`);
