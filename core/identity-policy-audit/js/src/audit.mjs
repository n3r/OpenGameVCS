import {
  canonicalBytes,
  sha256,
  validateAuditEvent,
} from '@opengamevcs/authorization-contract';

import { asIdentityError, identityFail } from './errors.mjs';
import { RUNTIME_LIMITS, cloneBounded, deepFreeze } from './validate.mjs';

const DOMAIN = Buffer.from('OGVCS-IDENTITY-AUDIT-CHAIN-V1\0', 'ascii');
const ID = /^[a-z][a-z0-9.-]{0,127}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;

const DISCLOSURE = Object.freeze({
  'policy.changed': Object.freeze(['changeRef']),
  'lock.force-unlocked': Object.freeze(['targetClass']),
  'export.requested': Object.freeze(['targetClass', 'changeRef']),
  'export.completed': Object.freeze([]),
  'retention.deleted': Object.freeze(['changeRef']),
  'impersonation.started': Object.freeze(['actorPseudonym']),
  'impersonation.ended': Object.freeze(['actorPseudonym']),
  'repair.executed': Object.freeze(['changeRef']),
  'audit.accessed': Object.freeze(['targetClass']),
  'grant.revoked': Object.freeze(['targetClass']),
  'authority.epoch-changed': Object.freeze(['changeRef']),
});

function tenantName(tenant) {
  if (typeof tenant !== 'string' || !ID.test(tenant)) identityFail('INPUT_INVALID', 'audit tenant is invalid');
  return tenant;
}

function recordHash(core) { return sha256(Buffer.concat([DOMAIN, canonicalBytes(core)])); }

function inspectRecord(record, tenant, maximumBytes = RUNTIME_LIMITS.maxAuditRecordBytes) {
  try {
    const keys = Object.keys(record).sort().join('\0');
    if (keys !== ['event', 'eventHash', 'previousHash', 'recordHash', 'schemaVersion', 'sequence', 'tenant'].sort().join('\0')) throw new Error('field set');
    const event = validateAuditEvent(record.event);
    const core = {
      schemaVersion: record.schemaVersion,
      tenant: record.tenant,
      sequence: record.sequence,
      previousHash: record.previousHash,
      eventHash: record.eventHash,
      event,
    };
    if (record.schemaVersion !== 'ogvcs.identity-policy/audit-chain-record/v1' || record.tenant !== tenant
        || event.tenant !== tenant || !Number.isSafeInteger(record.sequence) || record.sequence < 1
        || !(record.previousHash === null || SHA256.test(record.previousHash))
        || record.eventHash !== sha256(canonicalBytes(event)) || record.recordHash !== recordHash(core)
        || canonicalBytes(record).length > maximumBytes) throw new Error('record mismatch');
    return { core, event };
  } catch (error) {
    identityFail('AUDIT_INTEGRITY', 'audit record validation failed', { cause: error });
  }
}

function inspectCheckpoint(checkpointInput, tenant) {
  try {
    const checkpoint = cloneBounded(checkpointInput, { maxBytes: 1_024, maxDepth: 4, maxNodes: 16, maxStringBytes: 256 });
    const keys = Object.keys(checkpoint).sort().join('\0');
    if (keys !== ['schemaVersion', 'tenant', 'records', 'tailHash'].sort().join('\0')
        || checkpoint.schemaVersion !== 'ogvcs.identity-policy/audit-checkpoint/v1'
        || checkpoint.tenant !== tenant || !ID.test(checkpoint.tenant)
        || !Number.isSafeInteger(checkpoint.records) || checkpoint.records < 0
        || !(checkpoint.tailHash === null || SHA256.test(checkpoint.tailHash))) throw new Error('checkpoint mismatch');
    return checkpoint;
  } catch (error) {
    identityFail('AUDIT_INTEGRITY', 'audit checkpoint validation failed', { cause: error });
  }
}

function projectEvent(event) {
  const approved = DISCLOSURE[event.eventClass];
  if (!approved) identityFail('AUDIT_INTEGRITY', 'audit event has no disclosure assignment');
  const disclosure = {};
  if (approved.includes('actorPseudonym')) disclosure.actorPseudonym = event.actorPseudonym;
  if (approved.includes('targetClass')) disclosure.targetClass = event.details.targetClass;
  if (approved.includes('changeRef') && event.details.changeRef !== null) disclosure.changeRef = event.details.changeRef;
  return deepFreeze({
    schemaVersion: 'ogvcs.identity-policy/authorized-audit-event/v1',
    eventClass: event.eventClass,
    occurredAt: event.occurredAt,
    repository: event.repository,
    permission: event.permission,
    outcomeCode: event.outcomeCode,
    disclosure,
  });
}

export class MemoryAuditStore {
  #byTenant = new Map();

  tail(tenant) {
    const records = this.#byTenant.get(tenant) ?? [];
    return records.length === 0 ? null : structuredClone(records.at(-1));
  }

  appendExpected(tenant, expectedPreviousHash, record) {
    const records = this.#byTenant.get(tenant) ?? [];
    const actual = records.length === 0 ? null : records.at(-1).recordHash;
    if (actual !== expectedPreviousHash) identityFail('STATE_CONFLICT', 'audit tail changed');
    records.push(structuredClone(record));
    this.#byTenant.set(tenant, records);
  }

  list(tenant, maximum) {
    const records = this.#byTenant.get(tenant) ?? [];
    if (records.length > maximum) identityFail('LIMIT_EXCEEDED', 'audit query bound exceeded');
    return structuredClone(records);
  }

  unsafeReplaceForTest(tenant, records) { this.#byTenant.set(tenant, structuredClone(records)); }
}

export class AuditLedger {
  #maximum;
  #store;

  constructor({ store, maxRecordBytes = RUNTIME_LIMITS.maxAuditRecordBytes }) {
    if (!store || typeof store.tail !== 'function' || typeof store.appendExpected !== 'function' || typeof store.list !== 'function') identityFail('INPUT_INVALID', 'audit store adapter is invalid');
    if (!Number.isSafeInteger(maxRecordBytes) || maxRecordBytes < 1 || maxRecordBytes > RUNTIME_LIMITS.maxAuditRecordBytes) identityFail('INPUT_INVALID', 'audit record bound is invalid');
    this.#store = store; this.#maximum = maxRecordBytes;
  }

  append(eventInput) {
    let event;
    try { event = validateAuditEvent(eventInput); }
    catch (error) { identityFail('INPUT_INVALID', 'audit event is invalid', { cause: error }); }
    let tail;
    try { tail = this.#store.tail(event.tenant); }
    catch (error) { identityFail('AUDIT_INTEGRITY', 'audit tail read failed', { cause: error }); }
    if (tail !== null) inspectRecord(tail, event.tenant, this.#maximum);
    const core = {
      schemaVersion: 'ogvcs.identity-policy/audit-chain-record/v1',
      tenant: event.tenant,
      sequence: (tail?.sequence ?? 0) + 1,
      previousHash: tail?.recordHash ?? null,
      eventHash: sha256(canonicalBytes(event)),
      event,
    };
    const record = { ...core, recordHash: recordHash(core) };
    if (canonicalBytes(record).length > this.#maximum) identityFail('LIMIT_EXCEEDED', 'audit record bound exceeded');
    try { this.#store.appendExpected(event.tenant, core.previousHash, record); }
    catch (error) { throw asIdentityError(error, 'AUDIT_INTEGRITY'); }
    return deepFreeze(structuredClone(record));
  }

  checkpoint(tenant) {
    tenantName(tenant);
    let tail;
    try { tail = this.#store.tail(tenant); }
    catch (error) { throw asIdentityError(error, 'AUDIT_INTEGRITY'); }
    if (tail !== null) inspectRecord(tail, tenant, this.#maximum);
    return Object.freeze({
      schemaVersion: 'ogvcs.identity-policy/audit-checkpoint/v1',
      tenant,
      records: tail?.sequence ?? 0,
      tailHash: tail?.recordHash ?? null,
    });
  }

  verify(tenant, { maxRecords = RUNTIME_LIMITS.maxAuditQueryRecords, expectedCheckpoint = null } = {}) {
    tenantName(tenant);
    if (!Number.isSafeInteger(maxRecords) || maxRecords < 1 || maxRecords > RUNTIME_LIMITS.maxAuditQueryRecords) identityFail('INPUT_INVALID', 'audit verification bound is invalid');
    const { records, previousHash } = this.#verifiedRecords(tenant, maxRecords, expectedCheckpoint);
    return Object.freeze({ valid: true, records: records.length, tailHash: previousHash });
  }

  viewForAuthorizedRequest(tenant, { engine, principal, credentialAuthority, request, expectedCheckpoint, maxRecords = RUNTIME_LIMITS.maxAuditQueryRecords }) {
    tenantName(tenant);
    if (!engine || !principal || !credentialAuthority) identityFail('AUTHENTICATION_DENIED');
    if (!Number.isSafeInteger(maxRecords) || maxRecords < 1 || maxRecords > RUNTIME_LIMITS.maxAuditQueryRecords) identityFail('INPUT_INVALID', 'audit query bound is invalid');
    if (expectedCheckpoint === null || expectedCheckpoint === undefined) identityFail('POLICY_UNAVAILABLE', 'authorized audit views require a trusted checkpoint');
    let requestValue;
    let scoped;
    try {
      requestValue = cloneBounded(request);
      scoped = { ...requestValue, actor: cloneBounded(principal.actor, { maxBytes: 64 * 1024 }) };
    }
    catch (error) { throw asIdentityError(error, 'INPUT_INVALID'); }
    if (requestValue.tenant !== tenant || requestValue.permission !== 'audit.read'
        || requestValue.resource?.type !== 'audit') identityFail('AUTHENTICATION_DENIED');
    const decision = engine.authorize(scoped, {
      credentialCheck: (validated) => credentialAuthority.authorizePrincipal(principal, validated),
    });
    if (!decision.allowed) identityFail('AUTHENTICATION_DENIED');
    const { events } = this.#verifiedRecords(tenant, maxRecords, expectedCheckpoint);
    try {
      return deepFreeze({
        schemaVersion: 'ogvcs.identity-policy/authorized-audit-view/v1',
        items: events
          .filter((event) => event.repository === requestValue.repository)
          .map(projectEvent),
      });
    } catch (error) { throw asIdentityError(error, 'AUDIT_INTEGRITY'); }
  }

  #verifiedRecords(tenant, maxRecords, expectedCheckpoint) {
    const checkpoint = expectedCheckpoint === null ? null : inspectCheckpoint(expectedCheckpoint, tenant);
    let records;
    try {
      records = this.#store.list(tenant, maxRecords);
      if (!Array.isArray(records)) throw new TypeError('audit store list is not an array');
      if (records.length > maxRecords) identityFail('LIMIT_EXCEEDED', 'audit query bound exceeded');
    } catch (error) {
      if (error?.code === 'LIMIT_EXCEEDED') throw error;
      identityFail('AUDIT_INTEGRITY', 'audit store read failed', { cause: error });
    }
    let previousHash = null;
    const events = [];
    try {
      for (let index = 0; index < records.length; index += 1) {
        const record = records[index];
        const inspected = inspectRecord(record, tenant, this.#maximum);
        if (record.sequence !== index + 1 || record.previousHash !== previousHash) {
          identityFail('AUDIT_INTEGRITY', 'audit chain verification failed');
        }
        previousHash = record.recordHash;
        events.push(inspected.event);
      }
    } catch (error) {
      if (error?.code === 'AUDIT_INTEGRITY') throw error;
      identityFail('AUDIT_INTEGRITY', 'audit chain verification failed', { cause: error });
    }
    if (checkpoint !== null) {
      if (checkpoint.records !== records.length || checkpoint.tailHash !== previousHash) {
        identityFail('AUDIT_INTEGRITY', 'audit checkpoint differs');
      }
    }
    return { records, events, previousHash };
  }
}
