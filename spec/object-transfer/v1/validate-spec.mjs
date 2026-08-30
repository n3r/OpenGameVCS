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
const CONTRACT_VERSION = '0.1.0-rc.4';
const profile = (await load('profiles/filesystem-v1.json')).value;
if (profile.profile !== 'storage.opengamevcs/filesystem@1' || profile.candidateState !== 'development-not-production-write-eligible' || profile.backendKey.algorithm !== 'HMAC-SHA-256' || profile.backendKey.domainAscii !== 'OGVCS-OBJECT-BACKEND-KEY-V1' || profile.backendKey.domainNulTerminated !== true || profile.containment.directoryIdentityPinned !== true || profile.containment.finalComponentNoFollow !== true || profile.containment.sameAuthorityConcurrentAncestorMutation !== 'requires-native-directory-handle-relative-adapter' || profile.durability.create !== 'file-sync+atomic-link-no-replace+directory-sync-on-create-or-eexist' || profile.durability.delete !== 'authoritative-one-use-permit+durable-intent+generation-bound-unlink+directory-sync' || profile.durability.windowsDirectorySync !== 'suppress-only-EPERM-after-verified-directory-open' || profile.locking.commitFence !== 'current-token-before-and-after-persisted-commit' || profile.locking.lease !== 'renewed-while-operation-live' || profile.locking.takeover !== 'rename+post-rename-renewal-recheck' || profile.grantAuthority.clock !== 'service-owned' || profile.grantAuthority.singleUseReplay !== 'persistent-atomic-exclusive-claim' || profile.limits.objectBytesMaximum !== 67108864 || profile.limits.partBytesMaximum !== 4194304 || profile.limits.rangeBytesMaximum !== 8388608 || profile.limits.sessionsPerTenantMaximum !== 256 || profile.limits.nonceRecordsMaximum !== 4096 || profile.limits.lifecycleRecordsMaximum !== 4096 || profile.limits.deleteIntentsMaximum !== 4096 || profile.limits.workingMemoryBytesMaximum !== 268435456) fail('filesystem profile constants are invalid');
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
  ['faults', 'ogvcs.object-transfer/fault-vectors/v1', 2],
  ['hostile', 'ogvcs.object-transfer/hostile-vectors/v1', 2],
  ['lifecycle', 'ogvcs.object-transfer/lifecycle-vectors/v1', 2],
  ['resume', 'ogvcs.object-transfer/resume-vectors/v1', 2],
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
  next: expected.objects.map(({ nextGeneration, nextState, priorState, reachabilityRecorded }) => ({
    priorState, nextState, nextGeneration, reachabilityRecorded,
  })),
}))) !== canonical([
  { id: 'submit-consume-publication', capability: 'submit.consume-publication', method: 'consumePublication', objects: 2, next: [{ priorState: 'available', nextState: 'available', nextGeneration: 2, reachabilityRecorded: true }, { priorState: 'quarantined', nextState: 'available', nextGeneration: 8, reachabilityRecorded: true }] },
  { id: 'gc-acquire-deleting', capability: 'gc.acquire-deleting', method: 'acquireDeleting', objects: 1, next: [{ priorState: 'quarantined', nextState: 'deleting', nextGeneration: 3, reachabilityRecorded: false }] },
  { id: 'gc-complete-deletion', capability: 'gc.complete-deletion', method: 'completeDeletion', objects: 1, next: [{ priorState: 'deleting', nextState: 'deleted', nextGeneration: 3, reachabilityRecorded: false }] },
  { id: 'transfer-reverify-deleted', capability: 'transfer.reverify-deleted', method: 'reverifyDeleted', objects: 1, next: [{ priorState: 'deleted', nextState: 'staged', nextGeneration: 3, reachabilityRecorded: false }] },
  { id: 'transfer-record-available', capability: 'transfer.record-available', method: 'recordAvailable', objects: 1, next: [{ priorState: 'staged', nextState: 'available', nextGeneration: 3, reachabilityRecorded: false }] },
])) fail('transaction participant vectors are not exact');
const lifecycleSchema = (await load('schemas/lifecycle-record.schema.json')).value; const sessionSchema = (await load('schemas/session-record.schema.json')).value; const lockSchema = (await load('schemas/lock-owner.schema.json')).value; const nonceSchema = (await load('schemas/nonce-claim.schema.json')).value; const deleteIntentSchema = (await load('schemas/delete-intent.schema.json')).value; const fenceSchema = (await load('schemas/backend-lifecycle-fence.schema.json')).value; const transactionContextSchema = (await load('schemas/lifecycle-transaction-context.schema.json')).value; const transactionResultSchema = (await load('schemas/lifecycle-transaction-adapter-result.schema.json')).value; await load('schemas/vector-set.schema.json');
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
    || !transactionResultSchema.properties.capability?.enum?.includes('transfer.reverify-deleted')) fail('persisted-state schemas omit hardened fields');
const manifest = (await load('manifest.json')).value;
if (manifest.contractVersion !== CONTRACT_VERSION || manifest.profile !== profile.profile || manifest.predecessorContracts.authorization !== '1.0.0' || manifest.predecessorContracts.protocol !== '1.0.0-rc.1') fail('manifest header is invalid');
if (new Set(manifest.artifacts.map(({ path }) => path)).size !== manifest.artifacts.length || manifest.artifacts.some(({ path }, index) => !/^[A-Za-z0-9._/-]+$/u.test(path) || path.startsWith('/') || path.split('/').includes('..') || index > 0 && manifest.artifacts[index - 1].path >= path)) fail('artifact inventory is unsafe');
for (const artifact of manifest.artifacts) { const body = await readFile(resolve(ROOT, artifact.path)); if (body.length !== artifact.bytes || sha(body) !== artifact.sha256) fail(`${artifact.path} differs from manifest`); if (artifact.path.endsWith('.json') && artifact.path !== 'package.json') await load(artifact.path); }
const artifactSetSha256 = sha(Buffer.concat(manifest.artifacts.map((item) => Buffer.from(`${item.path}\0${item.sha256}\0${item.bytes}\n`))));
if (artifactSetSha256 !== manifest.artifactSetSha256 || manifest.counts.artifacts !== manifest.artifacts.length || manifest.counts.backendCases !== 3 || manifest.counts.faultCases !== 9 || manifest.counts.hostileCases !== 19 || manifest.counts.lifecycleCases !== 2 || manifest.counts.resumeCases !== 2 || manifest.counts.schemas !== 9 || manifest.counts.transactionCases !== 5) fail('manifest counts or digest differ');
process.stdout.write(`${canonical({ artifactSetSha256, objectId, opaqueKey: expectedKey, profile: profile.profile })}\n`);
