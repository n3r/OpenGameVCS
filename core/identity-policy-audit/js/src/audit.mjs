import {
  canonicalBytes,
  sha256,
  validateAuditEvent,
} from '@opengamevcs/authorization-contract';

import { asIdentityError, identityFail } from './errors.mjs';
import { RUNTIME_LIMITS, deepFreeze } from './validate.mjs';

const DOMAIN = Buffer.from('OGVCS-IDENTITY-AUDIT-CHAIN-V1\0', 'ascii');

function recordHash(core) { return sha256(Buffer.concat([DOMAIN, canonicalBytes(core)])); }

function inspectRecord(record, tenant) {
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
        || !(record.previousHash === null || /^[0-9a-f]{64}$/u.test(record.previousHash))
        || record.eventHash !== sha256(canonicalBytes(event)) || record.recordHash !== recordHash(core)) throw new Error('record mismatch');
    return { core, event };
  } catch (error) {
    identityFail('AUDIT_INTEGRITY', 'audit record validation failed', { cause: error });
  }
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
    if (tail !== null) inspectRecord(tail, event.tenant);
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
    let tail;
    try { tail = this.#store.tail(tenant); }
    catch (error) { throw asIdentityError(error, 'AUDIT_INTEGRITY'); }
    if (tail !== null) inspectRecord(tail, tenant);
    return Object.freeze({
      schemaVersion: 'ogvcs.identity-policy/audit-checkpoint/v1',
      tenant,
      records: tail?.sequence ?? 0,
      tailHash: tail?.recordHash ?? null,
    });
  }

  verify(tenant, { maxRecords = RUNTIME_LIMITS.maxAuditQueryRecords, expectedCheckpoint = null } = {}) {
    if (!Number.isSafeInteger(maxRecords) || maxRecords < 1 || maxRecords > RUNTIME_LIMITS.maxAuditQueryRecords) identityFail('INPUT_INVALID', 'audit verification bound is invalid');
    let records;
    try { records = this.#store.list(tenant, maxRecords); }
    catch (error) {
      if (error?.code === 'LIMIT_EXCEEDED') throw error;
      identityFail('AUDIT_INTEGRITY', 'audit store read failed', { cause: error });
    }
    let previousHash = null;
    for (let index = 0; index < records.length; index += 1) {
      const record = records[index];
      inspectRecord(record, tenant);
      if (record.sequence !== index + 1 || record.previousHash !== previousHash) {
        identityFail('AUDIT_INTEGRITY', 'audit chain verification failed');
      }
      previousHash = record.recordHash;
    }
    if (expectedCheckpoint !== null && (expectedCheckpoint?.schemaVersion !== 'ogvcs.identity-policy/audit-checkpoint/v1'
        || expectedCheckpoint.tenant !== tenant || expectedCheckpoint.records !== records.length
        || expectedCheckpoint.tailHash !== previousHash)) identityFail('AUDIT_INTEGRITY', 'audit checkpoint differs');
    return Object.freeze({ valid: true, records: records.length, tailHash: previousHash });
  }

  recordsForAuthorizedRequest(tenant, { engine, principal, credentialAuthority, request, maxRecords = RUNTIME_LIMITS.maxAuditQueryRecords }) {
    if (!engine || !principal || !credentialAuthority || request?.tenant !== tenant
        || request?.permission !== 'audit.read' || request?.resource?.type !== 'audit') identityFail('AUTHENTICATION_DENIED');
    if (!Number.isSafeInteger(maxRecords) || maxRecords < 1 || maxRecords > RUNTIME_LIMITS.maxAuditQueryRecords) identityFail('INPUT_INVALID', 'audit query bound is invalid');
    const scoped = { ...structuredClone(request), actor: structuredClone(principal.actor) };
    const decision = engine.authorize(scoped, {
      credentialCheck: (validated) => credentialAuthority.authorizePrincipal(principal, validated),
    });
    if (!decision.allowed) identityFail('AUTHENTICATION_DENIED');
    let records;
    try { records = this.#store.list(tenant, maxRecords); }
    catch (error) { throw asIdentityError(error, 'AUDIT_INTEGRITY'); }
    try { return deepFreeze(records.filter((record) => inspectRecord(record, tenant).event.repository === request.repository)); }
    catch (error) { throw asIdentityError(error, 'AUDIT_INTEGRITY'); }
  }
}
