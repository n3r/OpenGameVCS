import { canonicalBytes, sha256, validateAuditEvent } from '@opengamevcs/authorization-contract';

import { asIdentityError, identityFail } from './errors.mjs';
import { RUNTIME_LIMITS, cloneBounded, deepFreeze } from './validate.mjs';

const ID = /^[a-z][a-z0-9.-]{0,127}$/u;
const OPAQUE = /^[A-Za-z0-9._:-]{1,256}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const PSEUDONYM = /^pseudonym:[0-9a-f]{32}$/u;

function authorize(value, expected) {
  const result = cloneBounded(value, { maxBytes: 8_192, maxDepth: 5, maxNodes: 64, maxStringBytes: 256 });
  const keys = Object.keys(result).sort();
  const fields = ['allowed', 'actorClass', 'actorPseudonym', 'correlationId', 'decisionDigest', 'tenant', 'repository', 'permission'].sort();
  if (keys.length !== fields.length || keys.some((key, index) => key !== fields[index]) || result.allowed !== true
      || !['human', 'administrator', 'service'].includes(result.actorClass) || !PSEUDONYM.test(result.actorPseudonym ?? '')
      || !OPAQUE.test(result.correlationId ?? '') || !SHA256.test(result.decisionDigest ?? '')
      || result.tenant !== expected.tenant || result.repository !== expected.repository || result.permission !== 'policy.administer') {
    identityFail('AUTHENTICATION_DENIED', 'security mutation authorization is invalid');
  }
  return deepFreeze(result);
}

function time(clock) {
  let value;
  try { value = clock(); }
  catch (error) { identityFail('POLICY_UNAVAILABLE', 'security authority clock failed closed', { cause: error }); }
  if (!Number.isSafeInteger(value) || value < 0) identityFail('POLICY_UNAVAILABLE', 'security authority clock is invalid');
  return value;
}

export class SecurityMutationAuthority {
  #authorizer;
  #clock;
  #store;

  constructor({ store, authorizer, clock = () => Math.floor(Date.now() / 1_000) }) {
    if (!store || typeof store.authority !== 'function' || typeof store.credential !== 'function'
        || typeof store.revokeCredentialWithAudit !== 'function' || typeof store.promoteWithAudit !== 'function'
        || !authorizer || typeof authorizer.authorizeSecurityMutation !== 'function' || typeof clock !== 'function') {
      identityFail('INPUT_INVALID', 'security mutation authority dependencies are invalid');
    }
    this.#store = store; this.#authorizer = authorizer; this.#clock = clock;
  }

  revokeCredential(input) {
    const request = cloneBounded(input, { maxBytes: 16_384, maxDepth: 6, maxNodes: 128, maxStringBytes: 256 });
    const expected = ['revocationId', 'tenant', 'repository', 'credentialId', 'reason'].sort();
    const keys = Object.keys(request).sort();
    if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])
        || !OPAQUE.test(request.revocationId ?? '') || !ID.test(request.tenant ?? '') || !ID.test(request.repository ?? '')
        || !ID.test(request.credentialId ?? '') || typeof request.reason !== 'string' || request.reason.trim() === ''
        || Buffer.byteLength(request.reason, 'utf8') > 256) identityFail('INPUT_INVALID', 'credential revocation is invalid');
    const state = this.#authority(request.tenant);
    let authorization;
    try { authorization = authorize(this.#authorizer.authorizeSecurityMutation({ operation: 'credential.revoke', request, authority: state }), request); }
    catch (error) { throw asIdentityError(error, 'AUTHENTICATION_DENIED'); }
    const record = this.#credential(request.tenant, request.credentialId);
    const effectiveAt = time(this.#clock);
    const requestDigest = sha256(canonicalBytes(request));
    const event = validateAuditEvent({
      schemaVersion: 'ogvcs.authorization/audit-event/v1', eventId: request.revocationId,
      eventClass: 'grant.revoked', occurredAt: effectiveAt, tenant: request.tenant, repository: request.repository,
      actorClass: authorization.actorClass, actorPseudonym: authorization.actorPseudonym,
      permission: 'policy.administer', reason: request.reason, outcomeCode: 'ALLOW_EXPLICIT',
      correlationId: authorization.correlationId,
      details: { targetClass: record?.credentialClass ?? 'credential', changeRef: null },
    });
    let receipt;
    try {
      receipt = this.#store.revokeCredentialWithAudit({
        request, expectedAuthorityEpoch: state.authorityEpoch,
        expectedCredentialGeneration: record?.generation ?? null,
        effectiveAt, maximumAuthorizingUntil: effectiveAt + RUNTIME_LIMITS.revocationMaximumLagSeconds,
        authorization, event, requestDigest,
      });
    } catch (error) { throw asIdentityError(error, 'STATE_CONFLICT'); }
    if (!receipt || !Number.isSafeInteger(receipt.credentialGeneration) || receipt.credentialGeneration < 1
        || receipt.authorityEpoch !== state.authorityEpoch || receipt.requestDigest !== requestDigest
        || !SHA256.test(receipt.auditRecordHash ?? '')
        || receipt.maximumAuthorizingUntil !== effectiveAt + RUNTIME_LIMITS.revocationMaximumLagSeconds) {
      identityFail('POLICY_UNAVAILABLE', 'credential revocation receipt is invalid');
    }
    return deepFreeze({
      schemaVersion: 'ogvcs.identity-policy/revocation-receipt/v1', revocationId: request.revocationId,
      tenant: request.tenant, credentialId: request.credentialId,
      credentialGeneration: receipt.credentialGeneration, authorityEpoch: receipt.authorityEpoch,
      effectiveAt, maximumAuthorizingUntil: receipt.maximumAuthorizingUntil,
      auditRecordHash: receipt.auditRecordHash,
    });
  }

  promote(input) {
    const request = cloneBounded(input, { maxBytes: 16_384, maxDepth: 5, maxNodes: 64, maxStringBytes: 256 });
    const expected = ['promotionId', 'tenant', 'repository', 'authorityEpoch', 'keyGeneration', 'reason', 'recoveryBoundaryDigest'].sort();
    const keys = Object.keys(request).sort();
    if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])
        || !OPAQUE.test(request.promotionId ?? '') || !ID.test(request.tenant ?? '') || !ID.test(request.repository ?? '')
        || !Number.isSafeInteger(request.authorityEpoch) || request.authorityEpoch < 2
        || !Number.isSafeInteger(request.keyGeneration) || request.keyGeneration < 2
        || typeof request.reason !== 'string' || request.reason.trim() === '' || Buffer.byteLength(request.reason, 'utf8') > 256
        || !SHA256.test(request.recoveryBoundaryDigest ?? '')) identityFail('INPUT_INVALID', 'authority promotion is invalid');
    const state = this.#authority(request.tenant);
    if (request.authorityEpoch <= state.authorityEpoch || request.keyGeneration <= state.keyGeneration) {
      identityFail('STATE_CONFLICT', 'authority promotion must advance epoch and key generation');
    }
    let authorization;
    try { authorization = authorize(this.#authorizer.authorizeSecurityMutation({ operation: 'authority.promote', request, authority: state }), request); }
    catch (error) { throw asIdentityError(error, 'AUTHENTICATION_DENIED'); }
    const effectiveAt = time(this.#clock);
    const requestDigest = sha256(canonicalBytes(request));
    const event = validateAuditEvent({
      schemaVersion: 'ogvcs.authorization/audit-event/v1', eventId: request.promotionId,
      eventClass: 'authority.epoch-changed', occurredAt: effectiveAt, tenant: request.tenant, repository: request.repository,
      actorClass: authorization.actorClass, actorPseudonym: authorization.actorPseudonym,
      permission: 'policy.administer', reason: request.reason, outcomeCode: 'ALLOW_EXPLICIT', correlationId: authorization.correlationId,
      details: { targetClass: 'authority', changeRef: request.promotionId },
    });
    let receipt;
    try {
      receipt = this.#store.promoteWithAudit({ request, expectedAuthorityEpoch: state.authorityEpoch, authorization, event, effectiveAt, requestDigest });
    } catch (error) { throw asIdentityError(error, 'STATE_CONFLICT'); }
    if (!receipt || receipt.authorityEpoch !== request.authorityEpoch || receipt.keyGeneration !== request.keyGeneration
        || receipt.requestDigest !== requestDigest || !SHA256.test(receipt.auditRecordHash ?? '')) identityFail('POLICY_UNAVAILABLE', 'authority promotion receipt is invalid');
    return deepFreeze({
      schemaVersion: 'ogvcs.identity-policy/epoch-promotion-receipt/v1', promotionId: request.promotionId,
      tenant: request.tenant, previousAuthorityEpoch: state.authorityEpoch,
      authorityEpoch: request.authorityEpoch, keyGeneration: request.keyGeneration,
      effectiveAt, auditRecordHash: receipt.auditRecordHash,
      recoveryBoundaryDigest: request.recoveryBoundaryDigest,
    });
  }

  #authority(tenant) {
    let state;
    try { state = this.#store.authority(tenant); }
    catch (error) { identityFail('POLICY_UNAVAILABLE', 'authority state is unavailable', { cause: error }); }
    if (!state || !Number.isSafeInteger(state.authorityEpoch) || state.authorityEpoch < 1
        || !Number.isSafeInteger(state.keyGeneration) || state.keyGeneration < 1) identityFail('POLICY_UNAVAILABLE', 'authority state is invalid');
    return deepFreeze(cloneBounded(state));
  }

  #credential(tenant, id) {
    let record;
    try { record = this.#store.credential(tenant, id); }
    catch (error) { identityFail('POLICY_UNAVAILABLE', 'credential state is unavailable', { cause: error }); }
    if (record === null) return null;
    if (!record || !Number.isSafeInteger(record.generation) || record.generation < 1
        || !['session', 'service-token'].includes(record.credentialClass)) identityFail('POLICY_UNAVAILABLE', 'credential state is invalid');
    return deepFreeze(cloneBounded(record));
  }
}
