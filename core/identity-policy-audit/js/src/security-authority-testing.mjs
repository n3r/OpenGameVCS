import { AuditLedger, MemoryAuditStore } from './audit.mjs';
import { identityFail } from './errors.mjs';

export class MemorySecurityMutationStore {
  #audit = new MemoryAuditStore();
  #authority = new Map();
  #credentials = new Map();
  #revocations = new Map();
  #promotions = new Map();

  initializeAuthority(tenant, state) { this.#authority.set(tenant, structuredClone(state)); }
  putCredential(tenant, record) { this.#credentials.set(`${tenant}\0${record.id}`, structuredClone(record)); }
  authority(tenant) { return this.#authority.has(tenant) ? structuredClone(this.#authority.get(tenant)) : null; }
  credential(tenant, id) { return this.#credentials.has(`${tenant}\0${id}`) ? structuredClone(this.#credentials.get(`${tenant}\0${id}`)) : null; }

  revokeCredentialWithAudit({ request, expectedAuthorityEpoch, expectedCredentialGeneration, effectiveAt, maximumAuthorizingUntil, event, requestDigest }) {
    const replay = this.#revocations.get(request.revocationId);
    if (replay) {
      if (replay.requestDigest !== requestDigest) identityFail('STATE_CONFLICT');
      return structuredClone(replay);
    }
    const authority = this.#authority.get(request.tenant);
    if (!authority || authority.authorityEpoch !== expectedAuthorityEpoch) identityFail('STATE_CONFLICT');
    const key = `${request.tenant}\0${request.credentialId}`; const current = this.#credentials.get(key);
    const generation = current?.generation ?? 1;
    if (current && current.generation !== expectedCredentialGeneration) identityFail('STATE_CONFLICT');
    const record = new AuditLedger({ store: this.#audit }).append(event);
    if (current) this.#credentials.set(key, { ...current, state: 'revoked' });
    const receipt = { credentialGeneration: generation, authorityEpoch: expectedAuthorityEpoch, maximumAuthorizingUntil, auditRecordHash: record.recordHash, effectiveAt, requestDigest };
    this.#revocations.set(request.revocationId, receipt); return structuredClone(receipt);
  }

  promoteWithAudit({ request, expectedAuthorityEpoch, event, requestDigest }) {
    const replay = this.#promotions.get(request.promotionId);
    if (replay) {
      if (replay.requestDigest !== requestDigest) identityFail('STATE_CONFLICT');
      return structuredClone(replay);
    }
    const current = this.#authority.get(request.tenant);
    if (!current || current.authorityEpoch !== expectedAuthorityEpoch) identityFail('STATE_CONFLICT');
    const record = new AuditLedger({ store: this.#audit }).append(event);
    this.#authority.set(request.tenant, { ...current, authorityEpoch: request.authorityEpoch, keyGeneration: request.keyGeneration });
    const receipt = { authorityEpoch: request.authorityEpoch, keyGeneration: request.keyGeneration, auditRecordHash: record.recordHash, requestDigest };
    this.#promotions.set(request.promotionId, receipt); return structuredClone(receipt);
  }

  auditLedger() { return new AuditLedger({ store: this.#audit }); }
}
