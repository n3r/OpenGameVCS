import {
  canonicalBytes,
  sha256,
  validateAuditEvent,
} from '@opengamevcs/authorization-contract';

import { asIdentityError, identityFail } from './errors.mjs';
import { PolicyEngine } from './policy.mjs';
import { RUNTIME_LIMITS, cloneBounded, deepFreeze, validatePolicyDocument } from './validate.mjs';

const ID = /^[a-z][a-z0-9.-]{0,127}$/u;
const OPAQUE = /^[A-Za-z0-9._:-]{1,256}$/u;
const PSEUDONYM = /^pseudonym:[0-9a-f]{32}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;

function mutationInput(input) {
  const value = cloneBounded(input, { maxBytes: 4 * 1024 * 1024, maxDepth: 20, maxNodes: 100_000, maxStringBytes: 4_096 });
  const expected = ['schemaVersion', 'mutationId', 'tenant', 'repository', 'expectedGeneration', 'nextPolicy', 'previewRequests', 'reason', 'diffRef'].sort();
  const keys = Object.keys(value).sort();
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])
      || value.schemaVersion !== 'ogvcs.identity-policy/policy-mutation/v1'
      || !OPAQUE.test(value.mutationId ?? '') || !ID.test(value.tenant ?? '') || !ID.test(value.repository ?? '')
      || !Number.isSafeInteger(value.expectedGeneration) || value.expectedGeneration < 1
      || !Array.isArray(value.previewRequests) || value.previewRequests.length > RUNTIME_LIMITS.maxPolicyPreviewRequests
      || typeof value.reason !== 'string' || value.reason.trim() === '' || Buffer.byteLength(value.reason, 'utf8') > 256
      || !OPAQUE.test(value.diffRef ?? '')) identityFail('INPUT_INVALID', 'policy mutation is invalid');
  value.nextPolicy = validatePolicyDocument(value.nextPolicy);
  return deepFreeze(value);
}

function safePreview(engine, request, generation, authorityEpoch) {
  const candidate = cloneBounded(request);
  if (!candidate.context || typeof candidate.context !== 'object' || !candidate.actor || typeof candidate.actor !== 'object') {
    identityFail('INPUT_INVALID', 'policy preview request is invalid');
  }
  candidate.context.policyGeneration = generation;
  candidate.context.authorityEpoch = authorityEpoch;
  candidate.actor.authorityEpoch = authorityEpoch;
  const decision = engine.authorize(candidate, { credentialCheck: () => true });
  return Object.freeze({
    requestId: decision.requestId,
    allowed: decision.allowed,
    code: decision.code,
    fingerprint: decision.decisionFingerprint,
  });
}

function inspectAuthorization(value, mutation) {
  const result = cloneBounded(value, { maxBytes: 8_192, maxDepth: 5, maxNodes: 64, maxStringBytes: 256 });
  const expected = ['allowed', 'actorClass', 'actorPseudonym', 'correlationId', 'decisionDigest', 'tenant', 'repository', 'permission'].sort();
  const keys = Object.keys(result).sort();
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])
      || result.allowed !== true || !['human', 'administrator', 'service'].includes(result.actorClass)
      || !PSEUDONYM.test(result.actorPseudonym ?? '') || !OPAQUE.test(result.correlationId ?? '')
      || !SHA256.test(result.decisionDigest ?? '') || result.tenant !== mutation.tenant
      || result.repository !== mutation.repository || result.permission !== 'policy.administer') {
    identityFail('AUTHENTICATION_DENIED', 'policy mutation authorization is invalid');
  }
  return deepFreeze(result);
}

export class PolicyMutationAuthority {
  #authorizer;
  #clock;
  #store;

  constructor({ store, authorizer, clock = () => Math.floor(Date.now() / 1_000) }) {
    if (!store || typeof store.read !== 'function' || typeof store.compareAndSwapWithAudit !== 'function'
        || !authorizer || typeof authorizer.authorizePolicyMutation !== 'function' || typeof clock !== 'function') {
      identityFail('INPUT_INVALID', 'policy mutation authority dependencies are invalid');
    }
    this.#store = store; this.#authorizer = authorizer; this.#clock = clock;
  }

  preview(input) {
    const mutation = mutationInput(input); const current = this.#current(mutation.tenant);
    const preview = this.#preview(mutation, current);
    try {
      inspectAuthorization(this.#authorizer.authorizePolicyMutation({ operation: 'policy.preview', mutation, currentPolicy: current, preview }), mutation);
    } catch (error) { throw asIdentityError(error, 'AUTHENTICATION_DENIED'); }
    return preview;
  }

  commit(input) {
    const mutation = mutationInput(input); const current = this.#current(mutation.tenant);
    if (current.generation !== mutation.expectedGeneration
        || mutation.nextPolicy.generation !== current.generation + 1
        || mutation.nextPolicy.authorityEpoch !== current.authorityEpoch
        || mutation.nextPolicy.id !== current.id) identityFail('STATE_CONFLICT', 'policy generation changed or mutation is non-monotonic');
    const preview = this.#preview(mutation, current);
    let authorization;
    try { authorization = inspectAuthorization(this.#authorizer.authorizePolicyMutation({ operation: 'policy.commit', mutation, currentPolicy: current, preview }), mutation); }
    catch (error) { throw asIdentityError(error, 'AUTHENTICATION_DENIED'); }
    const occurredAt = this.#now();
    const event = validateAuditEvent({
      schemaVersion: 'ogvcs.authorization/audit-event/v1',
      eventId: mutation.mutationId,
      eventClass: 'policy.changed',
      occurredAt,
      tenant: mutation.tenant,
      repository: mutation.repository,
      actorClass: authorization.actorClass,
      actorPseudonym: authorization.actorPseudonym,
      permission: 'policy.administer',
      reason: mutation.reason,
      outcomeCode: 'ALLOW_EXPLICIT',
      correlationId: authorization.correlationId,
      details: { targetClass: 'policy', changeRef: mutation.diffRef },
    });
    let committed;
    try {
      committed = this.#store.compareAndSwapWithAudit({
        tenant: mutation.tenant,
        expectedGeneration: mutation.expectedGeneration,
        nextPolicy: mutation.nextPolicy,
        authorization,
        event,
      });
    } catch (error) { throw asIdentityError(error, 'STATE_CONFLICT'); }
    if (!committed || committed.policyGeneration !== mutation.nextPolicy.generation
        || !SHA256.test(committed.auditRecordHash ?? '')) identityFail('POLICY_UNAVAILABLE', 'policy commit receipt is invalid');
    return deepFreeze({
      schemaVersion: 'ogvcs.identity-policy/policy-mutation-receipt/v1',
      mutationId: mutation.mutationId,
      tenant: mutation.tenant,
      repository: mutation.repository,
      policyGeneration: mutation.nextPolicy.generation,
      authorityEpoch: mutation.nextPolicy.authorityEpoch,
      previewDigest: sha256(canonicalBytes(preview)),
      decisionDigest: authorization.decisionDigest,
      auditRecordHash: committed.auditRecordHash,
      committedAt: occurredAt,
    });
  }

  #preview(mutation, current) {
    if (current.generation !== mutation.expectedGeneration) identityFail('STATE_CONFLICT', 'policy generation changed');
    if (mutation.nextPolicy.generation !== current.generation + 1
        || mutation.nextPolicy.authorityEpoch !== current.authorityEpoch) identityFail('STATE_CONFLICT', 'policy preview is non-monotonic');
    const currentEngine = new PolicyEngine(current); const nextEngine = new PolicyEngine(mutation.nextPolicy);
    return deepFreeze({
      schemaVersion: 'ogvcs.identity-policy/policy-preview/v1',
      mutationId: mutation.mutationId,
      currentGeneration: current.generation,
      nextGeneration: mutation.nextPolicy.generation,
      items: mutation.previewRequests.map((request) => Object.freeze({
        current: safePreview(currentEngine, request, current.generation, current.authorityEpoch),
        next: safePreview(nextEngine, request, mutation.nextPolicy.generation, mutation.nextPolicy.authorityEpoch),
      })),
    });
  }

  #current(tenant) {
    let value;
    try { value = this.#store.read(tenant); }
    catch (error) { identityFail('POLICY_UNAVAILABLE', 'policy store read failed closed', { cause: error }); }
    if (value === null) identityFail('POLICY_UNAVAILABLE', 'policy is unavailable');
    return validatePolicyDocument(value);
  }

  #now() {
    let value;
    try { value = this.#clock(); }
    catch (error) { identityFail('POLICY_UNAVAILABLE', 'policy clock failed closed', { cause: error }); }
    if (!Number.isSafeInteger(value) || value < 0) identityFail('POLICY_UNAVAILABLE', 'policy clock is invalid');
    return value;
  }
}
